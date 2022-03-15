#![feature(map_first_last)]
#![macro_use]
mod debug;
pub mod reassembler;

// configuration option:
// - connection
//
use pdu::*;
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::Path;
use std::process;
use std::rc::Rc;

struct MyListener {
    data: HashMap<reassembler::FlowKey, Vec<u8>>,
}

impl reassembler::Listener for MyListener {
    fn accept_tcp(&mut self, bytes: Vec<u8>, stream_key: reassembler::FlowKey) {
        let stream_bytes = self.data.entry(stream_key).or_default();
        for byte in bytes.clone().into_iter() {
            stream_bytes.push(byte);
        }
        // match String::from_utf8(bytes) {
        //     Ok(s) => {
        //         print!("{}", s);
        //     }
        //     Err(e) => println!("{}", e),
        // }
    }
}

pub struct PcapReassembler {}

impl PcapReassembler {
    pub fn read_file<P>(
        file: P,
        filter: Option<&str>,
        listener: Rc<RefCell<dyn reassembler::Listener>>,
    ) where
        P: AsRef<Path>,
    {
        // let file =
        //     File::open("/home/jo/master/tcp_reassembly_test_framework/attacks/test.pcap").unwrap();
        let rc = Rc::clone(&listener);
        let mut reassembler = reassembler::Reassembler::new(&rc);
        let mut reader = pcap::Capture::from_file(file).expect("capture");
        if let Some(filter) = filter {
            match reader.filter(filter, true) {
                Err(e) => {
                    println!("{:?}", e);
                    process::exit(1);
                }
                _ => {}
            }
        }

        let mut packet_num = 1;
        loop {
            match reader.next() {
                Ok(packet) => {
                    match EthernetPdu::new(&packet) {
                        Ok(ethernet_pdu) => {
                            packet_num += 1;
                            // upper-layer protocols can be accessed via the inner() method

                            match ethernet_pdu.inner() {
                                Ok(Ethernet::Ipv4(ipv4_pdu)) => {
                                    if ipv4_pdu.dont_fragment() && ipv4_pdu.more_fragments() {
                                        println!("illeagal flag combination");
                                    }
                                    if ipv4_pdu.more_fragments() {
                                        // TODO: handle Ip fragmentation
                                        unimplemented!();
                                    }
                                    if let Ok(Ipv4::Tcp(tcp_packet)) = ipv4_pdu.inner() {
                                        let computed_checksum =
                                            tcp_packet.computed_checksum(&Ip::Ipv4(ipv4_pdu));
                                        if tcp_packet.checksum() == computed_checksum {
                                            reassembler.process(ipv4_pdu);
                                        } else {
                                            debug_print!(
                                                "encountered wrong checksum in packet {}!",
                                                packet_num
                                            );
                                        }
                                    }
                                }
                                Ok(Ethernet::Ipv6(_ipv6_pdu)) => {
                                    // unimplemented!();
                                }
                                Ok(other) => {
                                    // panic!("Unexpected protocol {:?}", other);
                                }
                                Err(e) => {
                                    panic!("EthernetPdu::inner() parser failure: {:?}", e);
                                }
                            }
                        }
                        Err(e) => {
                            panic!("EthernetPdu::new() parser failure: {:?}", e);
                        }
                    }
                }
                Err(pcap::Error::NoMorePackets) => break,
                // TODO: add more error handling
                Err(e) => panic!("error while reading: {:?}", e),
            }
        }
        // TODO: use iterator
        // reassembler.trigger_reass();
        for (key, stream, _inconsistencies) in reassembler {
            println!("{:?}: {}", key, String::from_utf8_lossy(&stream));
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::reassembler::{FlowKey, Listener};
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::rc::Rc;
    use std::str;

    #[test]
    fn it_works() {
        let l = Rc::new(RefCell::new(super::MyListener {
            data: HashMap::new(),
        }));
        let file_name =
            "/home/jo/master/tcp_reassembly_test_framework/attacks/sturges-novak-model.pcap";
        super::PcapReassembler::read_file(
            file_name,
            None,
            Rc::clone(&l) as Rc<RefCell<dyn Listener>>,
        );
        let data = &Rc::clone(&l);
        // println!("{:?}", &data.borrow().data);
        if let Some(stream_data) = &data.borrow().data.get(&FlowKey {
            src: (Ipv4Addr::new(127, 0, 0, 1), 6001),
            dst: (Ipv4Addr::new(127, 0, 0, 1), 6000),
        }) {
            assert_eq!(
                str::from_utf8(&stream_data[..]).unwrap(),
                "0AAAJJBCCCLLLMMMFFFGGHHIQ"
            );
            return;
        };
        assert!(false);
    }
}
