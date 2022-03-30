use std::borrow::BorrowMut;
use std::net::Ipv4Addr;
use std::ops::DerefMut;
use std::path::Path;

use pcap::{Capture, Device, Savefile};
use pnet::datalink::{self, NetworkInterface};
use pnet::ipnetwork::IpNetwork;
use pnet::packet::tcp::TcpFlags;
use pnet::packet::{ethernet, ipv4, tcp, MutablePacket, Packet};
use pnet::util::MacAddr;
use rand::{thread_rng, Rng};

fn main() {
    // TODO: option to not fix checksum? to run checksum test (maybe check if it was correct in the
    // first place
    let mut mymac = None;
    let mut myip = None;
    //    pkts_scheduled = setup_sched();

    //   relative_sched();
    for iface in datalink::interfaces()
        .into_iter()
        .filter(|iface| iface.name == "wlp2s0")
    //.collect()
    {
        mymac = iface.mac;

        match iface.ips.into_iter().find(|ip| ip.is_ipv4()) {
            Some(IpNetwork::V4(ip)) => myip = Some(ip),
            _ => panic!("no ipv4 address found"),
        }
    }
    println!("{:?}, {:?}", mymac, myip);

    let cap_inactive = Capture::from_device("wlp2s0");

    rewrite(
        Ipv4Addr::new(127, 0, 0, 1),
        MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff),
        Ipv4Addr::new(127, 0, 0, 1),
        MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff),
        "newfile.pcap",
        5555,
    );

    let mut sched_list = setup_sched().expect("failed to setup schedule");

    let exp_rseq = sched_list[1].exp_rseq;
    relative_sched(&mut sched_list, exp_rseq);

    // Start replay by sending the first pakcet

    // let cap_active = cap_inactive.unwrap().open().unwrap();
    // if sched_list[0].remote_or_local == SchedType::Local {
    //     cap_active.sendpacket(buf);
    // }
}

fn relative_sched(sched_list: &mut Vec<Sched>, first_rseq: u32) {
    println!("relative_sched");
    let lseq_adjust: u32 = thread_rng().gen();
    println!("Random Local SEQ: {}", lseq_adjust);
    let first_lseq = sched_list.first().unwrap().curr_lseq;

    // make local packages absolute (initial seq is known)
    // make remote packages relative (we first have to wait on the initial seq)
    for sched in sched_list {
        match sched.remote_or_local {
            SchedType::Local => {
                sched.curr_lseq = sched
                    .curr_lseq
                    .wrapping_sub(first_lseq) // Fix to be relative
                    .wrapping_add(lseq_adjust); // Fix to be absolute
                sched.curr_lack = sched.curr_lack.wrapping_sub(first_rseq);

                // modify seq in packet buffer
                match sched.packet {
                    Some(ref mut buf) => match ethernet::MutableEthernetPacket::new(buf) {
                        Some(mut eth) => match ipv4::MutableIpv4Packet::new(eth.payload_mut()) {
                            Some(mut ipv4) => {
                                match tcp::MutableTcpPacket::new(ipv4.payload_mut()) {
                                    Some(mut tcp) => {
                                        tcp.set_sequence(sched.curr_lseq);
                                    }
                                    None => {}
                                }
                            }
                            None => {}
                        },
                        None => {}
                    },
                    None => {}
                }
                match sched.packet {
                    Some(ref mut buf) => fix_checksums(buf),
                    None => {}
                }
                // TODO: create minimal example of this and figure out how to do this without the
                // ref and pattern maching!
                // fix_checksums(sched.packet.unwrap().borrow_mut());

                sched.exp_rseq = sched.exp_rseq.wrapping_sub(first_rseq);
                sched.exp_rack = sched
                    .exp_rack
                    .wrapping_sub(first_rseq)
                    .wrapping_add(lseq_adjust);
            }
            SchedType::Remote => {
                sched.exp_rseq = sched.exp_rseq.wrapping_sub(first_rseq); // Fix to be relative
                sched.exp_rack = sched
                    .exp_rack
                    .wrapping_sub(first_rseq) // Fix to be relative
                    .wrapping_add(lseq_adjust); // Fix to be absolute
            }
        }
    }
}

#[derive(PartialEq)]
enum SchedType {
    Remote,
    Local,
}

struct Sched {
    curr_lseq: u32,
    curr_lack: u32,
    exp_rseq: u32,
    exp_rack: u32,
    remote_or_local: SchedType,
    length_last_ldata: u32,
    length_curr_ldata: u32,
    length_last_rdata: u32,
    length_curr_rdata: u32,
    packet: Option<Box<[u8]>>,
}

impl Sched {
    fn new(t: SchedType) -> Sched {
        Sched {
            curr_lseq: 0,
            curr_lack: 0,
            exp_rseq: 0,
            exp_rack: 0,
            remote_or_local: t,
            length_last_ldata: 0,
            length_curr_ldata: 0,
            length_last_rdata: 0,
            length_curr_rdata: 0,
            packet: None,
        }
    }
}

fn setup_sched() -> Option<Vec<Sched>> {
    // read file altered in rewrite()
    let mut cap_file = Capture::from_file("newfile.pcap").unwrap();
    let mut pkt_couter = 0;

    let mut local_ip = None;
    let mut remote_ip = None;

    while let Ok(packet) = cap_file.next() {
        let mut local = false;
        let mut remote = false;
        let mut sched_list = vec![];
        match ethernet::EthernetPacket::new(&packet) {
            Some(eth) => match ipv4::Ipv4Packet::new(eth.payload()) {
                Some(ipv4) => {
                    let sip = ipv4.get_source();
                    let dip = ipv4.get_destination();
                    match tcp::TcpPacket::new(ipv4.payload()) {
                        Some(tcp_packet) => {
                            // TODO: decide who is local and remote
                            if tcp_packet.get_flags() == TcpFlags::SYN {
                                local_ip = Some(sip);
                                remote_ip = Some(dip);
                            }

                            if local_ip == Some(sip) {
                                local = true;
                            }

                            if remote_ip == Some(dip) {
                                remote = true;
                            }
                            if !local && !remote {
                                panic!("fist packet was not a syn packet make sure that the pcap file includes only one flow starting with the 3-way handshake");
                            }
                            if local && remote {
                                // TODO: possible to take ports into accout to determine remote/ local
                                panic!("src and dst addresses are equal replaying against other machines not possible");
                            }
                            if tcp_packet.get_flags() == TcpFlags::SYN {
                                let mut sched = Sched::new(SchedType::Local);
                                sched.curr_lseq = tcp_packet.get_sequence();
                                sched.packet = Some(eth.packet().into());
                                sched_list.push(sched);
                            } else if local {
                                let mut sched = Sched::new(SchedType::Local);
                                sched.length_last_ldata = sched_list.last()?.length_last_rdata;
                                // sched.length_curr_ldata = size_payload;
                                sched.length_last_rdata = sched_list.last()?.length_curr_rdata;

                                sched.curr_lseq = tcp_packet.get_sequence();
                                sched.curr_lseq = tcp_packet.get_acknowledgement();
                                sched.exp_rseq = sched_list.last()?.exp_rseq;
                                sched.exp_rack = sched_list.last()?.exp_rack;
                                sched.packet = Some(eth.packet().into());
                                sched_list.push(sched);
                            } else if remote {
                                let mut sched = Sched::new(SchedType::Remote);
                                sched.length_last_ldata = sched_list.last()?.length_last_ldata;
                                sched.length_last_rdata = sched_list.last()?.length_last_rdata;
                                // sched.length_curr_rdata = size_payload;

                                sched.curr_lseq = sched_list.last()?.curr_lseq;
                                sched.curr_lack = sched_list.last()?.curr_lack;
                                sched.exp_rseq = tcp_packet.get_sequence();
                                sched.exp_rack = tcp_packet.get_acknowledgement();
                                sched.packet = Some(eth.packet().into());
                                sched_list.push(sched);
                            }
                        }

                        None => panic!("error parsing tcp packet"),
                    }
                }

                None => panic!("only ipv4 is supported"),
            },

            None => panic!("error parsing ethernet frame"),
        }

        pkt_couter += 1;
    }
    // TODO: fix return
    Some(vec![])
}

fn rewrite<P>(
    new_remoteip: Ipv4Addr,
    new_remotemac: MacAddr,
    myip: Ipv4Addr,
    mymac: MacAddr,
    file: P,
    new_src_port: u16,
) where
    P: AsRef<Path>,
{
    let mut syn_encountered = false;
    let mut local_ip = None;
    let mut remote_ip = None;
    let mut reader = Capture::from_file(
        "/home/jo/master/tcp_reassembly_test_framework/attacks/sturges-novak-model.pcap",
    )
    .expect("reader");
    if let Err(e) = reader.filter("tcp", true) {
        eprintln!("{:?}", e);
        panic!("Error applying filter to input file")
    }

    let save = Capture::dead(pcap::Linktype::ETHERNET).unwrap();
    let mut savefile = save.savefile(file);

    while let Ok(mut packet) = reader.next() {
        let mut local = false;
        let mut remote = false;
        let mut test = Vec::new();
        test.extend_from_slice(packet.data);
        match ethernet::MutableEthernetPacket::new(&mut test) {
            Some(mut eth) => {
                match ipv4::MutableIpv4Packet::new(eth.payload_mut()) {
                    Some(mut ipv4) => {
                        let test_local_ip = ipv4.get_source();
                        let test_remote_ip = ipv4.get_destination();

                        match tcp::MutableTcpPacket::new(ipv4.payload_mut()) {
                            Some(mut tcp) => {
                                if tcp.get_flags() == tcp::TcpFlags::SYN {
                                    syn_encountered = true;
                                    local_ip = Some(test_local_ip);
                                    remote_ip = Some(test_remote_ip);
                                }

                                if local_ip == Some(test_local_ip) {
                                    local = true;
                                }
                                if local_ip == Some(test_remote_ip) {
                                    remote = true;
                                }
                                if local && remote {
                                    // TODO: suppoert by checking the tuple
                                    panic!("same ip")
                                }

                                if local {
                                    tcp.set_source(new_src_port);
                                }
                                if remote {
                                    tcp.set_destination(new_src_port);
                                }

                                if syn_encountered {
                                    tcp.set_checksum(tcp::ipv4_checksum(
                                        &tcp.to_immutable(),
                                        &myip,
                                        &new_remoteip,
                                    ));
                                }
                            }
                            None => unimplemented!(),
                        }
                        if local {
                            ipv4.set_destination(new_remoteip);
                            ipv4.set_source(myip);
                        }
                        if remote {
                            ipv4.set_destination(myip);
                            ipv4.set_source(new_remoteip);
                        }
                        ipv4.set_checksum(ipv4::checksum(&ipv4.to_immutable()));
                    }
                    None => unimplemented!(),
                }
                if local {
                    eth.set_source(mymac);
                    eth.set_destination(new_remotemac);
                }
                if remote {
                    eth.set_source(new_remotemac);
                    eth.set_destination(mymac);
                }
                if syn_encountered {
                    match savefile {
                        Ok(ref mut s) => s.write(&pcap::Packet::new(packet.header, eth.packet())),
                        Err(ref e) => eprintln!("problem writing moified file! {}", e),
                    }
                }
            }
            None => unimplemented!(),
        }
    }
}

fn fix_checksums(buf: &mut [u8]) {
    match ethernet::MutableEthernetPacket::new(buf) {
        Some(mut eth) => match ipv4::MutableIpv4Packet::new(eth.payload_mut()) {
            Some(mut ipv4) => {
                let sip = ipv4.get_source();
                let dip = ipv4.get_destination();
                match tcp::MutableTcpPacket::new(ipv4.payload_mut()) {
                    Some(mut tcp) => {
                        tcp.set_checksum(tcp::ipv4_checksum(&tcp.to_immutable(), &sip, &dip));
                    }
                    None => {}
                }
                ipv4.set_checksum(ipv4::checksum(&ipv4.to_immutable()));
            }
            None => {}
        },
        None => {}
    };
}
