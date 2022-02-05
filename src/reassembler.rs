#![allow(dead_code)]
use pdu::Tcp;
use pdu::*;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::rc::Rc;
use std::rc::Weak;
use std::str;

/// TcpStream
/// delayed is able to store multiple data chunks with the same sequence number
struct TcpStream {
    delayed: BTreeMap<u32, Vec<Vec<u8>>>,
    next_seq: u32,
    listener: Weak<dyn Listener>,
}

impl TcpStream {
    fn new(listener: &Rc<dyn Listener>) -> TcpStream {
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
                println!("===flags=== {}", packet.flags());
                let Tcp::Raw(data) = packet.inner().unwrap();
                if let Ok(s) = str::from_utf8(data) {
                    println!("data: {}", s);
                }
                self.accept_packet(packet);
                self.next_seq += data.len() as u32;
                println!("next_seq updated {}", self.next_seq);
                self.check_delayed();
            } else {
                // out of order packet
                self.delayed
                    .entry(packet.sequence_number())
                    .or_default()
                    .push(packet.into_buffer().to_vec());
                //.insert(packet.sequence_number(), packet.into_buffer().to_vec());
            }
        }
    }

    fn accept_packet(&mut self, packet: pdu::TcpPdu) {
        println!(
            "overlap calc {} - {}",
            self.next_seq,
            packet.sequence_number()
        );
        let vec;
        let overlap = self.next_seq - packet.sequence_number();
        if let Ok(Tcp::Raw(data)) = packet.inner() {
            if overlap > 0 {
                if overlap > data.len() as u32 {
                    vec = Vec::new();
                } else {
                    let choosen_data = &data[overlap as usize..];
                    println!("choosen data: {:?} overlap: {}", choosen_data, overlap);
                    vec = choosen_data.to_vec();
                }
            } else {
                // adjust packet content
                vec = data.to_vec();
            }
            let num_bytes = vec.len();
            if let Some(l) = self.listener.upgrade() {
                l.accept_tcp(vec)
            }
            self.next_seq += num_bytes as u32;
        }

        if let Some(l) = self.listener.upgrade() {
            // l.notify(event);
        }
    }

    fn check_delayed(&mut self) {
        let mut found_something = false;
        if let Some(entry) = self.delayed.first_entry() {
            if entry.key() <= &self.next_seq {
                //TODO: accept data
                found_something = true;
                println!("found entry: {:?}", entry);
            } else {
                return;
            }
        } else {
            return;
        }
        if found_something {
            let p = self.delayed.pop_first();
            match p {
                Some(mut data_chuncks) => {
                    let chunk = data_chuncks.1.remove(0);
                    if !data_chuncks.1.is_empty() {
                        self.delayed.insert(data_chuncks.0, data_chuncks.1);
                    }
                    let packet = pdu::TcpPdu::new(&chunk).unwrap();
                    self.accept_packet(packet);
                }
                None => {}
            }
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
    listener: Weak<dyn Listener>,
}

pub struct Event;

pub trait Listener {
    fn notify(&self, event: &Event);
    fn accept_tcp(&self, bytes: Vec<u8>);
}

impl Reassembler {
    pub fn new(listener: &Rc<dyn Listener>) -> Reassembler {
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
            let stream = TcpStream::new(listener);
            let cur_stream = self.streams.entry(key.clone()).or_insert(stream);
            cur_stream.add(tcp_packet);
        }

        match self.listener.upgrade() {
            Some(listener) => listener.notify(&Event),
            None => println!("error reference dropped"),
        }
    }
    pub fn dispatch(&self, event: &Event) {
        match self.listener.upgrade() {
            Some(l) => l.notify(event),
            None => println!("no listener"),
        }
    }
}

// TODO: how to deal with wrapping sequence numbers
