use std::net::Ipv4Addr;
use std::path::Path;

use pcap::{Capture, Device, Savefile};
use pnet::datalink::{self, NetworkInterface};
use pnet::ipnetwork::IpNetwork;
use pnet::packet::tcp::TcpFlags;
use pnet::packet::{ethernet, ip, ipv4, tcp, MutablePacket, Packet};
use pnet::util::MacAddr;

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

    let cap_live = Capture::from_device("wlp2s0");

    rewrite(
        Ipv4Addr::new(127, 0, 0, 1),
        MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff),
        Ipv4Addr::new(127, 0, 0, 1),
        MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff),
        "newfile.pcap",
        5555,
    )
}

fn setup_sched() {
    let mut cap_file = Capture::from_file("xxx.pcap").unwrap();
    let mut pkt_couter = 0;

    let mut local_ip = None;
    let mut remote_ip = None;

    while let Ok(packet) = cap_file.next() {
        let mut local = false;
        let mut remote = false;
        packet.data;
        // TODO: parse packet
        match ethernet::EthernetPacket::new(&packet) {
            Some(eth) => match ipv4::Ipv4Packet::new(eth.payload()) {
                Some(ipv4) => match tcp::TcpPacket::new(ipv4.payload()) {
                    Some(tcp_packet) => {
                        // TODO: decide who is local and remote
                        if tcp_packet.get_flags() == TcpFlags::SYN {
                            local_ip = Some(ipv4.get_source());
                            remote_ip = Some(ipv4.get_destination());
                        }

                        if local_ip == Some(ipv4.get_source()) {
                            local = true;
                        }

                        if remote_ip == Some(ipv4.get_destination()) {
                            remote = true;
                        }
                        if !local && !remote {
                            panic!("fist packet was not a syn packet make sure that the pcap file includes only one flow starting with the 3-way handshake");
                        }
                        if local && remote {
                            // TODO: possible to take ports into accout to determine remote/ local
                            panic!("src and dst addresses are equal replaying against other machines not possible");
                        }

                        // TODO: remote local operations
                        // TODO: remote packet operations
                    }
                    None => panic!("error parsing tcp packet"),
                },
                None => panic!("only ipv4 is supported"),
            },

            None => panic!("error parsing ethernet frame"),
        }

        pkt_couter += 1;
    }
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
                    // TODO: save modified packet
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
