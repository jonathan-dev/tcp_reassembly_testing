use std::net::Ipv4Addr;
use std::path::Path;

use clap::Parser;
use log::info;
use pcap::Capture;
use pnet::datalink;
use pnet::ipnetwork::IpNetwork;
use pnet::packet::tcp::TcpFlags;
use pnet::packet::{ethernet, ipv4, tcp, MutablePacket, Packet};
use pnet::util::MacAddr;
use rand::{thread_rng, Rng};
use std::env;

static TMP_FILE: &str = "newfile.pcap";

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short = 'I', long)]
    interface: String,

    #[clap(short, long)]
    file: String,

    #[clap(short = 'i', long)]
    ip_dst: Ipv4Addr,

    #[clap(short, long)]
    mac_dst: MacAddr,

    #[clap(short, long)]
    port_src: u16,

    #[clap(short, long)]
    verbose: bool,
}

// TODO: option to not fix checksum? to run checksum test (maybe check if it was correct in the
// first place
// TODO: option to use none random sequence numbers For wrapping tests

fn main() {
    // arg parsing
    let args = Args::parse();
    if args.verbose {
        println!("verbose");
        env::set_var("RUST_LOG", "info");
    }
    env_logger::init();

    // get local ip and mac
    let (myip, mymac) = get_ip_and_mac(&args.interface);
    info!("local mac: {:?}, local ip {:?}", mymac, myip);

    rewrite(args.ip_dst, args.mac_dst, myip, mymac, args.file, 5555);

    let mut sched_list = setup_sched().expect("failed to setup schedule");

    let exp_rseq = sched_list[1].exp_rseq; // get expected remote sequence number (as basis for relative counting)
    relative_sched(&mut sched_list, exp_rseq);
    info!("Packets Scheduled");

    // Start replay by sending the first pakcet

    let cap_inactive = Capture::from_device(args.interface.as_str());
    // immediat_mode is needed (https://github.com/the-tcpdump-group/libpcap/issues/572)
    let mut cap_active = cap_inactive.unwrap().immediate_mode(true).open().unwrap();
    if sched_list[0].remote_or_local == SchedType::Local {
        match sched_list.first().unwrap().packet {
            Some(ref buf) => match cap_active.sendpacket(buf.as_ref()) {
                Ok(()) => {}
                Err(e) => eprintln!("Error sending fist syn ack packet {}", e),
            },
            None => unimplemented!(),
        };
    }

    let mut sched_index = 1;

    // === Packet Iteration Loop ===
    while sched_index < sched_list.len() {
        info!("idx: {}", sched_index);

        match sched_list[sched_index].remote_or_local {
            SchedType::Local => {
                // === Send Packet ===
                let curr_lack = sched_list[sched_index].curr_lack;
                match sched_list[sched_index].packet {
                    Some(ref mut buf) => {
                        adjust_ack(buf, curr_lack);
                        fix_checksums(buf);
                        match cap_active.sendpacket(buf.as_ref()) {
                            Ok(()) => {}
                            Err(e) => eprintln!("error sending packet {}", e),
                        }
                    }
                    None => unimplemented!(),
                };
                sched_index += 1;
            }

            SchedType::Remote => {
                info!("waiting for packet");
                // === Receive Packet ===
                match cap_active.next() {
                    Ok(packet) => {
                        match ethernet::EthernetPacket::new(&packet) {
                            Some(eth) => match ipv4::Ipv4Packet::new(eth.payload()) {
                                Some(ipv4) => match tcp::TcpPacket::new(ipv4.payload()) {
                                    Some(tcp) => {
                                        // SYN ACK
                                        if tcp.get_flags() == TcpFlags::SYN | TcpFlags::ACK {
                                            let initial_rseq = tcp.get_sequence();
                                            info!(
                                                "Received Remote Packet...............   {}",
                                                sched_index + 1
                                            );
                                            info!("Remote Packet Expectation met.");
                                            info!("Proceeding in replay....");
                                            info!("Remote Sequence number: {}", initial_rseq);
                                            // make schedule absolute based on received seq
                                            sched_list[1].exp_rseq =
                                                sched_list[1].exp_rseq.wrapping_add(initial_rseq);
                                            for mut sched in sched_list.iter_mut().skip(2) {
                                                match sched.remote_or_local {
                                                    SchedType::Local => {
                                                        sched.curr_lack = sched
                                                            .curr_lack
                                                            .wrapping_add(initial_rseq);
                                                    }
                                                    SchedType::Remote => {
                                                        sched.exp_rseq = sched
                                                            .exp_rseq
                                                            .wrapping_add(initial_rseq);
                                                    }
                                                }
                                            }
                                            sched_index += 1;
                                            continue;
                                        }
                                        info!(">Received a Remote Packet");
                                        info!(">>Checking Expectations");

                                        // Handle Remote Packet Loss

                                        // No Packet Loss... Proceed Normally
                                        if tcp.get_sequence() == sched_list[sched_index].exp_rseq
                                            && tcp.get_acknowledgement()
                                                == sched_list[sched_index].exp_rack
                                        {
                                            info!("Received Remote Packet (as expected)");
                                            if (sched_list[sched_index].exp_flags & TcpFlags::FIN)
                                                > 0
                                            {
                                                println!(
                                                    "{}",
                                                    String::from_utf8_lossy(tcp.payload())
                                                );
                                            }
                                            sched_index += 1;
                                        }
                                    }
                                    None => {}
                                },
                                None => {}
                            },
                            None => {}
                        };
                    }
                    Err(e) => {
                        eprintln!("{}", e)
                    }
                }
            }
        }
    }
}

/// Adjust schedule to be based on new initial seqence numbers. The local side will be based on a
/// randomly generated value and the remote side will be made based on 0 for the moment (realtive)
/// until the initial sequence number of the remote will be received.
fn relative_sched(sched_list: &mut Vec<Sched>, first_rseq: u32) {
    info!("relative_sched");
    let lseq_adjust: u32 = thread_rng().gen();
    info!("Random Local SEQ: {}", lseq_adjust);
    let first_lseq = sched_list.first().unwrap().curr_lseq;

    // make local packages absolute (initial seq is known)
    // make remote packages relative (we first have to wait on the initial seq)
    for mut sched in sched_list {
        match sched.remote_or_local {
            SchedType::Local => {
                sched.curr_lseq = sched
                    .curr_lseq
                    .wrapping_sub(first_lseq) // Fix to be relative
                    .wrapping_add(lseq_adjust); // Fix to be absolute
                sched.curr_lack = sched.curr_lack.wrapping_sub(first_rseq);

                // adjust packet buffer
                match sched.packet {
                    Some(ref mut buf) => {
                        adjust_seq(buf, sched.curr_lseq);
                        fix_checksums(buf);
                    }
                    None => {}
                }

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
                    .wrapping_sub(first_lseq) // Fix to be relative
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
    exp_flags: u16,
    remote_or_local: SchedType,
    packet: Option<Box<[u8]>>,
}

impl Sched {
    fn new(t: SchedType) -> Sched {
        Sched {
            curr_lseq: 0,
            curr_lack: 0,
            exp_rseq: 0,
            exp_rack: 0,
            exp_flags: 0,
            remote_or_local: t,
            packet: None,
        }
    }
}

fn setup_sched() -> Option<Vec<Sched>> {
    // read file altered in rewrite()
    let mut cap_file = Capture::from_file(TMP_FILE).unwrap();

    // local port and ip (to be determined on the first SYN packet)
    let mut local_ip = None;
    let mut local_port = None;

    let mut sched_list = vec![];
    while let Ok(packet) = cap_file.next() {
        // indication if packet is send by local or remote
        let mut local = false;
        let mut remote = false;
        match ethernet::EthernetPacket::new(&packet) {
            Some(eth) => match ipv4::Ipv4Packet::new(eth.payload()) {
                Some(ipv4) => {
                    // get src and dst pi for later
                    let sip = ipv4.get_source();
                    let dip = ipv4.get_destination();
                    match tcp::TcpPacket::new(ipv4.payload()) {
                        Some(tcp) => {
                            // decide who is local and remote
                            if tcp.get_flags() == TcpFlags::SYN {
                                local_ip = Some(sip);
                                local_port = Some(tcp.get_source());
                            }

                            if local_ip == Some(sip) && local_port == Some(tcp.get_source()) {
                                local = true;
                            } else if local_ip == Some(dip)
                                && local_port == Some(tcp.get_destination())
                            {
                                remote = true;
                            }
                            if !local && !remote {
                                panic!("fist packet was not a syn packet make sure that the pcap file includes only one flow starting with the 3-way handshake");
                            }
                            if local && remote {
                                panic!("src and dst addresses are equal replaying against other machines not possible");
                            }
                            // FIRST PACKET (SYN)
                            if tcp.get_flags() == TcpFlags::SYN {
                                let mut sched = Sched::new(SchedType::Local);
                                sched.curr_lseq = tcp.get_sequence();
                                sched.packet = Some(eth.packet().into());
                                sched_list.push(sched);
                            }
                            // LOCAL
                            else if local {
                                let mut sched = Sched::new(SchedType::Local);

                                sched.curr_lseq = tcp.get_sequence();
                                sched.curr_lack = tcp.get_acknowledgement();
                                sched.exp_rseq = sched_list.last()?.exp_rseq;
                                sched.exp_rack = sched_list.last()?.exp_rack;
                                sched.packet = Some(eth.packet().into());
                                sched_list.push(sched);
                            }
                            // REMOTE
                            else if remote {
                                let mut sched = Sched::new(SchedType::Remote);

                                sched.curr_lseq = sched_list.last()?.curr_lseq;
                                sched.curr_lack = sched_list.last()?.curr_lack;
                                sched.exp_rseq = tcp.get_sequence();
                                sched.exp_rack = tcp.get_acknowledgement();
                                sched.packet = Some(eth.packet().into());

                                sched.exp_flags = tcp.get_flags();
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
    }
    Some(sched_list)
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
    let mut local_port = None;
    let mut reader = Capture::from_file(file).expect("reader");
    if let Err(e) = reader.filter("tcp", true) {
        eprintln!("{:?}", e);
        panic!("Error applying filter to input file")
    }

    let save = Capture::dead(pcap::Linktype::ETHERNET).unwrap();
    let mut savefile = save.savefile(TMP_FILE);

    while let Ok(packet) = reader.next() {
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
                                // Determine local/remote
                                if tcp.get_flags() == tcp::TcpFlags::SYN {
                                    syn_encountered = true;
                                    local_ip = Some(test_local_ip);
                                    local_port = Some(tcp.get_source());
                                }

                                if local_ip == Some(test_local_ip)
                                    && local_port == Some(tcp.get_source())
                                {
                                    local = true;
                                } else if local_ip == Some(test_remote_ip)
                                    && local_port == Some(tcp.get_destination())
                                {
                                    remote = true;
                                }
                                if local && remote {
                                    panic!("same ip and port combination for local and remote")
                                }

                                if syn_encountered {
                                    // Set Port
                                    if local {
                                        tcp.set_source(new_src_port);
                                    }
                                    if remote {
                                        tcp.set_destination(new_src_port);
                                    }

                                    // Fix checksum TCP
                                    tcp.set_checksum(tcp::ipv4_checksum(
                                        &tcp.to_immutable(),
                                        &myip,
                                        &new_remoteip,
                                    ));
                                }
                            }
                            None => unimplemented!(),
                        }
                        // Set IP
                        if local {
                            ipv4.set_destination(new_remoteip);
                            ipv4.set_source(myip);
                        }
                        if remote {
                            ipv4.set_destination(myip);
                            ipv4.set_source(new_remoteip);
                        }
                        // Fix Checksum IP
                        ipv4.set_checksum(ipv4::checksum(&ipv4.to_immutable()));
                    }
                    None => unimplemented!(),
                }
                // Set MAC
                if local {
                    eth.set_source(mymac);
                    eth.set_destination(new_remotemac);
                }
                if remote {
                    eth.set_source(new_remotemac);
                    eth.set_destination(mymac);
                }
                // Save Packet
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

/// Takes a mutable packet buffer slice and trys to parses it as eth/ipv4/tcp and set the SEQ to the
/// given value
fn adjust_seq(buf: &mut [u8], seq: u32) {
    match ethernet::MutableEthernetPacket::new(buf) {
        Some(mut eth) => match ipv4::MutableIpv4Packet::new(eth.payload_mut()) {
            Some(mut ipv4) => match tcp::MutableTcpPacket::new(ipv4.payload_mut()) {
                Some(mut tcp) => tcp.set_sequence(seq),
                None => {}
            },
            None => {}
        },
        None => {}
    };
}

/// Takes a mutable packet buffer slice and trys to parses it as eth/ipv4/tcp and set the ACK to the
/// given value
fn adjust_ack(buf: &mut [u8], ack: u32) {
    match ethernet::MutableEthernetPacket::new(buf) {
        Some(mut eth) => match ipv4::MutableIpv4Packet::new(eth.payload_mut()) {
            Some(mut ipv4) => match tcp::MutableTcpPacket::new(ipv4.payload_mut()) {
                Some(mut tcp) => tcp.set_acknowledgement(ack),
                None => {}
            },
            None => {}
        },
        None => {}
    };
}

/// Takes a mutable packet buffer slice and parses it as eth/ipv4/tcp and recalculates the
/// checksums
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
fn get_ip_and_mac(interface: &str) -> (Ipv4Addr, MacAddr) {
    let mut mymac = None;
    let mut myip = None;
    for iface in datalink::interfaces()
        .into_iter()
        .filter(|iface| iface.name == interface)
    {
        mymac = iface.mac;

        match iface.ips.into_iter().find(|ip| ip.is_ipv4()) {
            Some(IpNetwork::V4(ip)) => myip = Some(ip),
            _ => panic!("no ipv4 address found"),
        }
    }
    match (myip, mymac) {
        (Some(ip), Some(mac)) => (ip.ip(), mac),
        _ => panic!("problem getting local ip and mac"),
    }
}
