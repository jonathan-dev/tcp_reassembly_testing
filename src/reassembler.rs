#![allow(dead_code)]
use pdu::Tcp;
use pdu::*;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::rc::Rc;
use std::rc::Weak;

/// TcpStream
/// delayed is able to store multiple data chunks with the same sequence number
struct TcpStream {
    delayed: BTreeMap<u32, Vec<Vec<u8>>>,
    next_seq: u32,
    listener: Weak<RefCell<dyn Listener>>,
}

impl TcpStream {
    fn new(listener: &Rc<RefCell<dyn Listener>>) -> TcpStream {
        TcpStream {
            delayed: BTreeMap::new(),
            next_seq: 11,
            listener: Rc::downgrade(&listener),
        }
    }

    fn add(&mut self, packet: pdu::TcpPdu) {
        if packet.psh() {
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
                    l.borrow_mut().accept_tcp(vec)
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

#[derive(PartialEq, Eq, Hash, Clone)]
struct FlowKey {
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
}

pub struct Reassembler {
    streams: HashMap<FlowKey, TcpStream>,
    listener: Weak<RefCell<dyn Listener>>,
}

pub struct Event;

pub trait Listener {
    fn accept_tcp(&mut self, bytes: Vec<u8>);
}

impl Reassembler {
    pub fn new(listener: &Rc<RefCell<dyn Listener>>) -> Reassembler {
        Reassembler {
            listener: Rc::downgrade(&listener),
            streams: HashMap::new(),
        }
    }
    pub fn process(&mut self, ip_packet: Ipv4Pdu) {
        if let Ok(Ipv4::Tcp(tcp_packet)) = ip_packet.inner() {
            let key = FlowKey {
                src_ip: ip_packet.source_address(),
                src_port: tcp_packet.source_port(),
                dst_ip: ip_packet.destination_address(),
                dst_port: tcp_packet.destination_port(),
            };
            let listener = &self.listener.upgrade().unwrap();
            // let stream = TcpStream::new(listener);
            let cur_stream = self.streams.entry(key).or_insert(TcpStream::new(listener));
            cur_stream.add(tcp_packet);
        }
    }
}

// TODO: how to deal with wrapping sequence numbers
