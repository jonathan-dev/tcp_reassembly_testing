use pdu::Tcp;
use pdu::*;
use std::collections::HashMap;
use std::rc::Rc;
use std::rc::Weak;

struct TcpStream {
    delayed: HashMap<u32, Vec<u8>>,
    next_seq: u32,
    listener: Weak<dyn Listener>,
}

impl TcpStream {
    fn new(listener: &Rc<dyn Listener>) -> TcpStream {
        TcpStream {
            delayed: HashMap::new(),
            next_seq: 11,
            listener: Rc::downgrade(&listener),
        }
    }
    fn add(&mut self, packet: pdu::TcpPdu) {
        if packet.sequence_number() == self.next_seq {
            println!("===flags=== {}", packet.flags());
            if let Tcp::Raw(data) = packet.inner().unwrap() {
                self.next_seq = self.next_seq + data.len() as u32;
                // TODO: check delayed
            }
        } else {
            if let Tcp::Raw(data) = packet.inner().unwrap() {
                println!("data {:?}", data);
                self.delayed.insert(packet.sequence_number(), data.to_vec());
            }
        }
    }

    fn check_delayed(&mut self) {
        // TODO: consider using BTreeMap for auto sorted iteration
        self.delayed.iter();
    }
}

#[derive(PartialEq, Eq, Hash)]
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
            let cur_stream = self
                .streams
                .entry(key)
                .or_insert(TcpStream::new(&self.listener.upgrade().unwrap()));
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

#[cfg(test)]
mod tests {
    use crate::reassembler::Event;
    use crate::reassembler::Listener;
    use crate::reassembler::Reassembler;
    use std::rc::Rc;
    //   #[test]
    //   fn test_listener() {
    //       let rc: Rc<dyn Listener> = Rc::new(MyListener {});
    //       let r = Reassembler::new(&rc);
    //       println!("===test_listener===");
    //       r.dispatch(&Event {});
    //       //r.init(m);
    //   }
}

// TODO: how to deal with wrapping sequence numbers
