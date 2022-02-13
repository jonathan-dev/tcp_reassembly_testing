#![allow(dead_code)]
use pdu::Tcp;
use pdu::*;
use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::rc::Rc;
use std::rc::Weak;

enum TcpState {
    SynRcvd,
    Estab,
    Closed,
}

/// TcpStream
/// delayed is able to store multiple data chunks with the same sequence number
struct TcpStream {
    state: TcpState,
    key: FlowKey,
    delayed: BTreeMap<u32, Vec<Vec<u8>>>,
    next_seq: u32,
    ack: u32,
    partner: Option<Weak<RefCell<TcpStream>>>,
    listener: Weak<RefCell<dyn Listener>>,
}

impl TcpStream {
    fn new(key: FlowKey, listener: &Rc<RefCell<dyn Listener>>) -> TcpStream {
        TcpStream {
            state: TcpState::Closed,
            key,
            delayed: BTreeMap::new(),
            next_seq: 0,
            ack: 0,
            partner: None,
            listener: Rc::downgrade(&listener),
        }
    }

    fn add(&mut self, packet: pdu::TcpPdu) {
        // set ack
        if packet.ack() {
            self.ack = packet.acknowledgement_number();
        }
        if packet.syn() && matches!(self.state, TcpState::Closed) {
            self.next_seq = packet.sequence_number() + 1;
            self.state = TcpState::SynRcvd;
            println!(
                "{} -> {} +++ SynRcvd +++",
                self.key.src_port, self.key.dst_port
            );
        }
        if matches!(self.state, TcpState::SynRcvd) {
            if let Some(partner) = &self.partner {
                // partner available
                let partner_seq = partner.upgrade().unwrap().borrow_mut().next_seq;
                if partner_seq == self.ack {
                    // do this in reverse!!!
                    self.state = TcpState::Estab;
                    println!(
                        "{} -> {} +++ Connection established +++",
                        self.key.src_port, self.key.dst_port
                    );
                }
            }
        }
        if packet.psh() && matches!(self.state, TcpState::Estab) {
            if packet.sequence_number() == self.next_seq {
                //packet in order
                self.accept_packet(packet);
                self.check_delayed();
            } else {
                // out of order packet
                self.delayed
                    .entry(packet.sequence_number())
                    .or_default()
                    .push(packet.into_buffer().to_vec());
            }
        }
    }

    fn accept_packet(&mut self, packet: pdu::TcpPdu) {
        let vec;
        let overlap = self.next_seq - packet.sequence_number();
        if let Ok(Tcp::Raw(data)) = packet.inner() {
            if overlap > 0 {
                if overlap > data.len() as u32 {
                    vec = Vec::new();
                } else {
                    let choosen_data = &data[overlap as usize..];
                    vec = choosen_data.to_vec();
                }
            } else {
                // adjust packet content
                vec = data.to_vec();
            }

            // update seq
            let num_bytes = vec.len();
            self.next_seq += num_bytes as u32;

            if let Some(l) = self.listener.upgrade() {
                if !vec.is_empty() {
                    l.borrow_mut().accept_tcp(vec, self.key.clone())
                }
            }
        }
    }

    fn check_delayed(&mut self) {
        if let Some(entry) = self.delayed.first_entry() {
            // check the first entry
            if entry.key() <= &self.next_seq {
                // take the fist entry (list of chunks) (multimap)
                let mut data_chunks = self.delayed.pop_first().unwrap();
                // take first data chunk
                let chunk = data_chunks.1.remove(0);
                // reinsert if we have multiple entries
                if !data_chunks.1.is_empty() {
                    self.delayed.insert(data_chunks.0, data_chunks.1);
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
}

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct FlowKey {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
}

impl FlowKey {
    fn swap_flow_key(&self) -> FlowKey {
        let tmp_ip = self.src_ip;
        let tmp_port = self.src_port;
        FlowKey {
            src_ip: self.dst_ip,
            src_port: self.dst_port,
            dst_ip: tmp_ip,
            dst_port: tmp_port,
        }
    }
}

pub struct Reassembler {
    streams: HashMap<FlowKey, Rc<RefCell<TcpStream>>>,
    listener: Weak<RefCell<dyn Listener>>,
}

pub struct Event;

pub trait Listener {
    fn accept_tcp(&mut self, bytes: Vec<u8>, stream_key: FlowKey);
}

impl Reassembler {
    pub fn new(listener: &Rc<RefCell<dyn Listener>>) -> Reassembler {
        Reassembler {
            listener: Rc::downgrade(&listener),
            streams: HashMap::new(),
        }
    }

    /// Choose or create stream in hashmap
    /// on newly created streams try to set the partner stream
    pub fn process(&mut self, ip_packet: Ipv4Pdu) {
        if let Ok(Ipv4::Tcp(tcp_packet)) = ip_packet.inner() {
            let key = FlowKey {
                src_ip: ip_packet.source_address(),
                src_port: tcp_packet.source_port(),
                dst_ip: ip_packet.destination_address(),
                dst_port: tcp_packet.destination_port(),
            };
            let mut new_stream = false;
            let listener = &self.listener.upgrade().unwrap();
            let cur_stream = match self.streams.entry(key.clone()) {
                Entry::Occupied(stream) => stream.into_mut().to_owned(),
                Entry::Vacant(v) => {
                    // try to find partner
                    new_stream = true;
                    v.insert(Rc::new(RefCell::new(TcpStream::new(key.clone(), listener))))
                        .to_owned()
                }
            };

            if new_stream {
                match self.streams.entry(key.swap_flow_key()) {
                    Entry::Occupied(partner) => {
                        // set Partner references
                        Rc::clone(&cur_stream).borrow_mut().partner =
                            Some(Rc::downgrade(partner.get()));
                        Rc::clone(&partner.get()).borrow_mut().partner =
                            Some(Rc::downgrade(&cur_stream));
                    }
                    Entry::Vacant(_v) => {}
                }
            }

            Rc::clone(&cur_stream).borrow_mut().add(tcp_packet);
        }
    }
}

// TODO: how to deal with wrapping sequence numbers
