#![allow(dead_code)]
use pdu::Tcp;
use pdu::*;
use std::cell::RefCell;
use std::cmp;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::iter::Iterator;
use std::iter::Zip;
use std::net::Ipv4Addr;
use std::ops::RangeFrom;
use std::rc::Rc;
use std::rc::Weak;
use std::slice::Iter;
use std::usize;

use crate::debug_print;

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
    reass_buff: Vec<u8>,
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
            reass_buff: vec![],
        }
    }

    /// initial packet add
    fn add(&mut self, packet: pdu::TcpPdu) {
        // set ack
        if packet.ack() {
            self.ack = packet.acknowledgement_number();
        }
        if packet.syn() && matches!(self.state, TcpState::Closed) {
            // TODO: use wrapping add!
            self.next_seq = packet.sequence_number() + 1;
            self.state = TcpState::SynRcvd;
            debug_print!("{} -> {} +++ SynRcvd +++", self.key.src.1, self.key.dst.1);
        }
        if matches!(self.state, TcpState::SynRcvd) {
            if let Some(partner) = &self.partner {
                // partner available
                let partner_seq = partner.upgrade().unwrap().borrow_mut().next_seq;
                if partner_seq == self.ack {
                    // do this in reverse!!!
                    self.state = TcpState::Estab;
                    debug_print!(
                        "{} -> {} +++ Connection established +++",
                        self.key.src.1,
                        self.key.dst.1
                    );
                }
            }
        }
        if packet.psh() && matches!(self.state, TcpState::Estab) {
            // if packet.sequence_number() <= self.next_seq {
            //     //packet in order
            //     self.accept_packet(packet);
            //     self.check_delayed();
            // } else {
            // out of order packet
            self.delayed
                .entry(packet.sequence_number())
                .or_default()
                .push(packet.into_buffer().to_vec());
            // }
        }
    }

    ///
    fn accept_packet(&mut self, packet: pdu::TcpPdu) {
        let mut vec;
        let overlap = self.next_seq - packet.sequence_number();
        if let Ok(Tcp::Raw(data)) = packet.inner() {
            if overlap > 0 {
                // TODO: check overlap for consistnecy
                let mut iter = data[..cmp::min(overlap as usize, data.len())]
                    .iter()
                    .zip(packet.sequence_number()..);
                self.check_overlap(&mut iter);
                if overlap > data.len() as u32 {
                    // packet completly overlaps with already received data
                    vec = Vec::new();
                } else {
                    // cut of overlaping part
                    let choosen_data = &data[overlap as usize..];
                    vec = choosen_data.to_vec();
                }
            } else {
                // adjust packet content
                vec = data.to_vec();
            }

            // update seq
            self.next_seq += vec.len() as u32;

            // TODO: consider not to clone if interface is changed to iterator
            self.reass_buff.append(&mut vec.clone());

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
                // reinsert (prev pop) if we have multiple entries
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

    fn check_overlap(&mut self, iter: &mut Zip<Iter<u8>, RangeFrom<u32>>) {
        for (byte, seq) in iter {
            let delta = self.next_seq - seq;
            let len = self.reass_buff.len();
            let orig = self.reass_buff[len - delta as usize];
            if byte != &orig {
                println!("found overlapping attack at sequence number {}. Byte found: {} previously received: {}", seq, byte, orig);
            }
        }
        // println!("{}", String::from_utf8_lossy(&self.reass_buff));
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Debug, PartialOrd, Ord)]
pub struct FlowKey {
    pub src: (Ipv4Addr, u16),
    pub dst: (Ipv4Addr, u16),
}

impl FlowKey {
    fn swap_flow_key(&self) -> FlowKey {
        FlowKey {
            dst: self.src,
            src: self.dst,
        }
    }
}

pub struct Reassembler {
    // TcpStream is Rc RefCell bcause of referencen in partner stream
    streams: BTreeMap<FlowKey, Rc<RefCell<TcpStream>>>,
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
            streams: BTreeMap::new(),
        }
    }

    /// Choose or create stream in hashmap
    /// on newly created streams try to set the partner stream
    pub fn process(&mut self, ip_packet: Ipv4Pdu) {
        if let Ok(Ipv4::Tcp(tcp_packet)) = ip_packet.inner() {
            let key = FlowKey {
                src: (
                    Ipv4Addr::from(ip_packet.source_address()),
                    tcp_packet.source_port(),
                ),
                dst: (
                    Ipv4Addr::from(ip_packet.destination_address()),
                    tcp_packet.destination_port(),
                ),
            };
            let mut new_stream = false;
            let listener = &self.listener.upgrade().unwrap();
            let cur_stream = match self.streams.entry(key.clone()) {
                Entry::Occupied(stream) => stream.into_mut().to_owned(),
                Entry::Vacant(v) => {
                    new_stream = true;
                    v.insert(Rc::new(RefCell::new(TcpStream::new(key.clone(), listener))))
                        .to_owned()
                }
            };

            // try to find partner
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
    pub fn trigger_reass(&mut self) {
        for s in self.streams.iter() {
            Rc::clone(s.1).borrow_mut().check_delayed();
        }
    }
}

impl Iterator for Reassembler {
    type Item = (FlowKey, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        let ret_val = match self.streams.pop_first() {
            Some((key, val)) => {
                let ss = Rc::clone(&val);
                let mut s = ss.borrow_mut();
                s.check_delayed();
                Some((key, s.reass_buff.clone()))
            }
            None => None,
        };
        ret_val
    }
}

// TODO: how to deal with wrapping sequence numbers
