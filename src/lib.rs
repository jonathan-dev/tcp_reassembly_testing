#![feature(map_first_last)]
mod reassembler;

struct MyListener;

impl reassembler::Listener for MyListener {
    fn accept_tcp(&self, bytes: Vec<u8>) {
        match String::from_utf8(bytes) {
            Ok(s) => print!("{}", s),
            Err(e) => println!("{}", e),
        }
    }
}
#[cfg(test)]
mod tests {
    use crate::reassembler;
    use pcap_parser::traits::PcapReaderIterator;
    use pcap_parser::*;
    use pdu::*;
    use std::fs::File;
    use std::rc::Rc;

    #[test]
    fn it_works() {
        let file =
            File::open("/home/jo/master/tcp_reassembly_test_framework/attacks/test.pcap").unwrap();
        let rc: Rc<dyn reassembler::Listener> = Rc::new(super::MyListener {});
        let mut reassembler = reassembler::Reassembler::new(&rc);
        let mut reader = LegacyPcapReader::new(65536, file).expect("LegacyPcapReader");
        loop {
            match reader.next() {
                Ok((offset, block)) => {
                    match block {
                        PcapBlockOwned::LegacyHeader(_hdr) => {}
                        PcapBlockOwned::Legacy(_b) => {
                            match EthernetPdu::new(_b.data) {
                                Ok(ethernet_pdu) => {
                                    // upper-layer protocols can be accessed via the inner() method
                                    match ethernet_pdu.inner() {
                                        Ok(Ethernet::Ipv4(ipv4_pdu)) => {
                                            reassembler.process(ipv4_pdu);
                                        }
                                        Ok(Ethernet::Ipv6(_ipv6_pdu)) => {
                                            unimplemented!();
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
        assert_eq!(2 + 2, 4);
    }
}
