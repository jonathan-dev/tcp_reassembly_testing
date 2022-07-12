/*!
This crate provides TCP stream reassembly for Pcap files.

This crate defines two primary types:

* [`PcapReassembler`] which only provides one method: [`PcapReassembler::read_file`] this method
  takes a pcap file and a Berkly filter and returns the other important type the [`Reassembler`]
* [`Reassembler`] contains all the reassembly logic. The interaction with it happens solely over the
  Iterator implementation it offers. The itterator returns a tuples of Tcp stream identification
  ([`reassembler::FlowKey`]), The reassembled Stream (as Vec<u8>) and a vector containing all inconsistencies
  ([`reassembler::Inconsistency`]) between retansmissions and the originally sent data.

Usage example:
```
use std::path::PathBuf;
use stream_reassembly::{self, PcapReassembler};

fn main() {
    let file = PathBuf::from("../../attacks/myattackment.pcap");
    // see https://biot.com/capstats/bpf.html for filter syntax
    let filter = Some("tcp port 6000 or tcp port 6001");

    let mut reassembler = PcapReassembler::read_file(file, filter);

    // print one direction
    if let Some(stream_data) = reassembler.next() {
        print!("{}", String::from_utf8_lossy(&stream_data.1))
    }
    // print the other direction
    if let Some(stream_data) = reassembler.next() {
        print!("{}", String::from_utf8_lossy(&stream_data.1))
    }
}
```
*/
#![feature(map_first_last)]
pub mod reassembler;

use env_logger;
use log::info;
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
        env_logger::try_init().unwrap_or(());
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
                                        info!("IPv4 fragmentation detected");
                                        unimplemented!();
                                    }
                                    if ipv4_pdu.checksum() != ipv4_pdu.computed_checksum() {
                                        info!(
                                            "encountered wrong checksum in IPv4 packet {}!",
                                            packet_num
                                        );
                                        continue;
                                    }
                                    if let Ok(Ipv4::Tcp(tcp_packet)) = ipv4_pdu.inner() {
                                        let computed_checksum_tcp =
                                            tcp_packet.computed_checksum(&Ip::Ipv4(ipv4_pdu));
                                        if tcp_packet.checksum() == computed_checksum_tcp {
                                            reassembler.process(ipv4_pdu);
                                        } else {
                                            info!(
                                                "encountered wrong checksum in TCP packet {}!",
                                                packet_num
                                            );
                                        }
                                    }
                                }
                                Ok(_other) => {
                                    // Just ignore packets other than ipv4
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
                Err(e) => panic!("error while reading: {:?}", e),
            }
        }
        reassembler
    }
}

#[cfg(test)]
mod tests {
    use crate::reassembler::FlowKey;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::str;

    #[test]
    fn basic_reassembly() {
        let file_name = "../test_framework/attacks/sturges-novak-model.pcap";
        let key_of_interest = FlowKey {
            src: SocketAddrV4::new(Ipv4Addr::new(192, 168, 8, 31), 6001),
            dst: SocketAddrV4::new(Ipv4Addr::new(192, 168, 8, 29), 6000),
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
    #[test]
    fn wrapping_reassembly() {
        let file_name = "../test_framework/attacks/sturges-novak-model-wrap_4294967281.pcap";
        let key_of_interest = FlowKey {
            src: SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 6001),
            dst: SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 6000),
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
