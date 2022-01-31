mod reassembler;
#[cfg(test)]
mod tests {
    use pcap_parser::traits::PcapReaderIterator;
    use pcap_parser::*;
    use pdu::*;
    use std::fs::File;

    #[test]
    fn it_works() {
        let file =
            File::open("/home/jo/master/tcp_reassembly_test_framework/attacks/test.pcap").unwrap();
        let mut num_blocks = 0;
        let mut reader = LegacyPcapReader::new(65536, file).expect("LegacyPcapReader");
        loop {
            match reader.next() {
                Ok((offset, block)) => {
                    println!("got new block");
                    num_blocks += 1;
                    match block {
                        PcapBlockOwned::LegacyHeader(_hdr) => {
                            // save hdr.network (linktype)
                            // println!("Magicnumber: {:X}", _hdr.magic_number);
                            //                           println!("Header: {:?}", _hdr);
                        }
                        PcapBlockOwned::Legacy(_b) => {
                            // use linktype to parse b.data()
                            //                            println!("Block: {:?}", _b);
                            // parse ipv4
                            // parse tcp
                            match EthernetPdu::new(_b.data) {
                                Ok(ethernet_pdu) => {
                                    println!(
                                        "[ethernet] destination_address: {:x?}",
                                        ethernet_pdu.destination_address().as_ref()
                                    );
                                    println!(
                                        "[ethernet] source_address: {:x?}",
                                        ethernet_pdu.source_address().as_ref()
                                    );
                                    println!(
                                        "[ethernet] ethertype: 0x{:04x}",
                                        ethernet_pdu.ethertype()
                                    );
                                    if let Some(vlan) = ethernet_pdu.vlan() {
                                        println!("[ethernet] vlan: 0x{:04x}", vlan);
                                    }
                                    // upper-layer protocols can be accessed via the inner() method
                                    match ethernet_pdu.inner() {
                                        Ok(Ethernet::Ipv4(ipv4_pdu)) => {
                                            println!(
                                                "[ipv4] source_address: {:x?}",
                                                ipv4_pdu.source_address().as_ref()
                                            );
                                            println!(
                                                "[ipv4] destination_address: {:x?}",
                                                ipv4_pdu.destination_address().as_ref()
                                            );
                                            println!(
                                                "[ipv4] protocol: 0x{:02x}",
                                                ipv4_pdu.protocol()
                                            );
                                            match ipv4_pdu.inner() {
                                                Ok(Ipv4::Tcp(tcp_pdu)) => {
                                                    println!(
                                                        "[tcp] seq: {}",
                                                        tcp_pdu.sequence_number()
                                                    );
                                                    println!("[tcp] flags: {}", tcp_pdu.flags());
                                                }
                                                Ok(_) => {
                                                    println!("unsupported protocol");
                                                }
                                                Err(e) => {
                                                    println!("an error occured: {:x?}", e);
                                                }
                                            }
                                            // upper-layer protocols can be accessed via the inner() method (not shown)
                                        }
                                        Ok(Ethernet::Ipv6(ipv6_pdu)) => {
                                            println!(
                                                "[ipv6] source_address: {:x?}",
                                                ipv6_pdu.source_address().as_ref()
                                            );
                                            println!(
                                                "[ipv6] destination_address: {:x?}",
                                                ipv6_pdu.destination_address().as_ref()
                                            );
                                            println!(
                                                "[ipv6] protocol: 0x{:02x}",
                                                ipv6_pdu.computed_protocol()
                                            );
                                            // upper-layer protocols can be accessed via the inner() method (not shown)
                                        }
                                        Ok(other) => {
                                            panic!("Unexpected protocol {:?}", other);
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
                        PcapBlockOwned::NG(_) => unreachable!(),
                    }
                    reader.consume(offset);
                }
                Err(PcapError::Eof) => break,
                Err(PcapError::Incomplete) => {
                    reader.refill().unwrap();
                }
                Err(e) => panic!("error while reading: {:?}", e),
            }
        }
        println!("num_blocks: {}", num_blocks);
        assert_eq!(2 + 2, 4);
    }
}
