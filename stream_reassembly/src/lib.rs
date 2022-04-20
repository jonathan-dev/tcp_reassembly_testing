#![feature(map_first_last)]
pub mod reassembler;

use log::info;
// configuration option:
// - connection
//
use env_logger;
use pdu::*;
use reassembler::Reassembler;
use std::path::Path;
use std::process;

pub struct PcapReassembler {}

impl PcapReassembler {
    pub fn read_file<P>(file: P, filter: Option<&str>) -> Reassembler
    where
        P: AsRef<Path>,
    {
        env_logger::init();
        let mut reassembler = reassembler::Reassembler::new();
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
                                            info!(
                                                "encountered wrong checksum in packet {}!",
                                                packet_num
                                            );
                                        }
                                    }
                                }
                                Ok(Ethernet::Ipv6(_ipv6_pdu)) => {
                                    // unimplemented!();
                                }
                                Ok(_other) => {
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
        reassembler
    }
}

#[cfg(test)]
mod tests {
    use crate::reassembler::FlowKey;
    use std::net::Ipv4Addr;
    use std::str;

    #[test]
    fn it_works() {
        let file_name =
            "/home/jo/master/tcp_reassembly_test_framework/attacks/sturges-novak-model.pcap";
        let key_of_interest = FlowKey {
            src: (Ipv4Addr::new(127, 0, 0, 1), 6001),
            dst: (Ipv4Addr::new(127, 0, 0, 1), 6000),
        };
        let mut reass = super::PcapReassembler::read_file(file_name, None);
        if let Some(stream_data) = reass.find(|(key, _, _)| key == &key_of_interest) {
            assert_eq!(
                str::from_utf8(&stream_data.1).unwrap(),
                "0AAAJJBCCCLLLMMMFFFGGHHIQ"
            );
            return;
        };
        assert!(false);
    }
}
