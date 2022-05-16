#![allow(dead_code)]
use log::info;
use pdu::Tcp;
use pdu::*;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::iter::Iterator;
use std::iter::Zip;
use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use std::ops::RangeFrom;
use std::slice::Iter;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::Weak;
use std::usize;

#[derive(PartialEq)]
enum TcpState {
    SynRcvd,
    Estab,
    Closed,
}

#[derive(Clone)]
pub struct Inconsistency {
    pub seq: u32,
    pub new: u8,
    pub orig: u8,
}

/// TcpStream
/// delayed is able to store multiple data chunks with the same sequence number
struct TcpStream {
    state: TcpState,
    key: FlowKey,
    delayed: BTreeMap<u32, Vec<Vec<u8>>>,
    next_seq: u32,
    ack: u32,
    partner: Option<Weak<Mutex<TcpStream>>>,
    reass_buff: Vec<u8>,
    inconsistencies: Vec<Inconsistency>,
    initial_seq: u32,
}

impl TcpStream {
    fn new(key: FlowKey, initial_seq: u32) -> TcpStream {
        TcpStream {
            state: TcpState::Closed,
            key,
            delayed: BTreeMap::new(),
            next_seq: 0,
            ack: 0,
            partner: None,
            reass_buff: vec![],
            inconsistencies: vec![],
            initial_seq,
        }
    }

    /// initial packet add
    fn add(&mut self, packet: pdu::TcpPdu) {
        // set ack
        if packet.ack() {
            self.ack = packet.acknowledgement_number();
        }
        // 3-way handshake
        if packet.syn() && self.state == TcpState::Closed {
            self.next_seq = packet
                .sequence_number()
                .wrapping_sub(self.initial_seq)
                .wrapping_add(1);
            self.state = TcpState::SynRcvd;
            info!(
                "{} -> {} +++ SynRcvd +++",
                self.key.src.ip(),
                self.key.dst.ip()
            );
            // handle data on syn (add packet to delayed)
            self.delayed
                .entry(1) // key should always be 1 (0 should be the initial seq)
                .or_default()
                .push(packet.into_buffer().to_vec());
        }
        if packet.ack() && self.state == TcpState::SynRcvd {
            if let Some(partner) = &self.partner {
                // partner available -> SYN ACK received
                let partner_seq = partner.upgrade().unwrap().lock().unwrap().next_seq;
                if partner_seq
                    == self
                        .ack
                        .wrapping_sub(partner.upgrade().unwrap().lock().unwrap().initial_seq)
                {
                    // do this in reverse!!!
                    self.state = TcpState::Estab;
                    info!(
                        "{} -> {} +++ Connection established +++",
                        self.key.src.ip(),
                        self.key.dst.ip()
                    );
                }
            }
        }
        // data packet
        if packet.psh() && self.state == TcpState::Estab {
            self.delayed
                .entry(packet.sequence_number().wrapping_sub(self.initial_seq))
                .or_default()
                .push(packet.into_buffer().to_vec());
        }
    }

    /// append packet that has the next seq number to the stream (overlap handling)
    fn accept_packet(&mut self, packet: pdu::TcpPdu) {
        let mut vec;
        // adjustment necessary to have the correct sequence number on syn packets with data
        let syn_add_one = match packet.syn() {
            true => 1,
            false => 0,
        };
        let overlap = self.next_seq
            - packet
                .sequence_number()
                .wrapping_sub(self.initial_seq)
                .wrapping_add(syn_add_one);
        if let Ok(Tcp::Raw(data)) = packet.inner() {
            if overlap > 0 {
                let mut overlap_data = data[..std::cmp::min(overlap as usize, data.len())]
                    .iter()
                    .zip(packet.sequence_number().wrapping_sub(self.initial_seq)..);
                self.check_overlap(&mut overlap_data);
                if overlap > data.len() as u32 {
                    // packet completly overlaps with already received data
                    vec = Vec::new();
                } else {
                    // cut of overlaping part
                    let choosen_data = &data[overlap as usize..];
                    vec = choosen_data.to_vec();
                }
            } else {
                vec = data.to_vec();
            }

            // update seq
            self.next_seq = self.next_seq.wrapping_add(vec.len() as u32);

            self.reass_buff.append(&mut vec);
        }
    }

    fn check_delayed(&mut self) {
        if let Some(entry) = self.delayed.first_entry() {
            // check the first entry
            if entry.key() <= &self.next_seq {
                // take the fist entry (list of chunks) (multimap)
                let (key, mut chunk_list) = self.delayed.pop_first().unwrap();
                // take first data chunk
                let chunk = chunk_list.remove(0);
                // reinsert remaining chunks if we have multiple entries
                if !chunk_list.is_empty() {
                    self.delayed.insert(key, chunk_list);
                }
                let packet = pdu::TcpPdu::new(&chunk).unwrap();
                self.accept_packet(packet);
            } else {
                return;
            }
        } else {
            return;
        }
        self.check_delayed();
    }

    /// get received byte ziped with its sequence number (calculated relative)
    fn check_overlap(&mut self, iter: &mut Zip<Iter<u8>, RangeFrom<u32>>) {
        for (byte, seq) in iter {
            let delta = self.next_seq - seq;
            let len = self.reass_buff.len();
            let orig = self.reass_buff[len - delta as usize];
            if byte != &orig {
                self.inconsistencies.push(Inconsistency {
                    seq,
                    new: byte.clone(),
                    orig,
                });
                info!("found overlapping attack at sequence number {}. Byte found: {} previously received: {}", seq, byte, orig);
            }
        }
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Debug, PartialOrd, Ord)]
pub struct FlowKey {
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
}

impl FlowKey {
    /// swap src and dst
    fn reverse_flow(&self) -> FlowKey {
        FlowKey {
            dst: self.src,
            src: self.dst,
        }
    }
}

pub struct Reassembler {
    /// TcpStream is Arc Mutex bcause of referencen in partner stream (Arc because of python
    /// interface)
    streams: BTreeMap<FlowKey, Arc<Mutex<TcpStream>>>,
}

impl Reassembler {
    pub fn new() -> Reassembler {
        Reassembler {
            streams: BTreeMap::new(),
        }
    }

    /// Choose or create stream in hashmap (depending on src port/ip and dst port/ip)
    /// on newly created streams try to set the partner stream
    pub fn process(&mut self, ip_packet: Ipv4Pdu) {
        if let Ok(Ipv4::Tcp(tcp_packet)) = ip_packet.inner() {
            let key = FlowKey {
                src: SocketAddrV4::new(
                    Ipv4Addr::from(ip_packet.source_address()),
                    tcp_packet.source_port(),
                ),
                dst: SocketAddrV4::new(
                    Ipv4Addr::from(ip_packet.destination_address()),
                    tcp_packet.destination_port(),
                ),
            };
            let cur_stream = match self.streams.entry(key.clone()) {
                Entry::Occupied(stream) => Some(stream.into_mut().to_owned()),
                Entry::Vacant(v) => {
                    if tcp_packet.syn() {
                        // new stream only on SYN

                        // assign stream to empty entry
                        let cur_stream = v
                            .insert(Arc::new(Mutex::new(TcpStream::new(
                                key.clone(),
                                tcp_packet.sequence_number(),
                            ))))
                            .to_owned();

                        // try finding partner stream
                        if let Entry::Occupied(partner) = self.streams.entry(key.reverse_flow()) {
                            // set Partner references
                            Arc::clone(&cur_stream).lock().unwrap().partner =
                                Some(Arc::downgrade(partner.get()));
                            Arc::clone(&partner.get()).lock().unwrap().partner =
                                Some(Arc::downgrade(&cur_stream));
                        }
                        Some(cur_stream)
                    } else {
                        None
                    }
                }
            };

            match cur_stream {
                Some(cur_stream) => Arc::clone(&cur_stream).lock().unwrap().add(tcp_packet),
                None => info!("Ignoring packet not belongingto any known stream"),
            }
        }
    }
}

impl Iterator for Reassembler {
    type Item = (FlowKey, Vec<u8>, Vec<Inconsistency>);

    fn next(&mut self) -> Option<Self::Item> {
        let ret_val = match self.streams.pop_first() {
            Some((key, val)) => {
                let stream_cloned = Arc::clone(&val);
                let mut stream_mut_ref = stream_cloned.lock().unwrap();
                // trigger reassembly
                stream_mut_ref.check_delayed();
                Some((
                    key,
                    stream_mut_ref.reass_buff.clone(),
                    stream_mut_ref.inconsistencies.clone(),
                ))
            }
            None => None,
        };
        ret_val
    }
}
