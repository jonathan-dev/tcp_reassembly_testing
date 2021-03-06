/**
 * This program has been implemented heavily coping from https://github.com/appneta/tcpreplay/blob/master/src/tcpliveplay.c
 *
 * Program Description:
 * This program replays a captured set of packets using new TCP connections against a live system
 * similar to 'tcpliveplay'. A difference between this program and 'tcpliveplay' is that this
 * programm expects one data packet after sending the FIN packet. This expected data packet is
 * expected to be the interpretation of the of the data already sent.
 * This program take in a "*.pcap" file that contains only one tcp flow connection and replays it
 * against a live host exactly how the captured packets are laid out. At the beginning, the program
 * establishes who the 'client is and the 'server' is based on who initiates the SYN compares each
 * packet's source ip against the ip of the client (which is named local in the code) and the
 * (remote) to correctly determine the expected seg & acks. This also extracts the MACs of both
 * local and reomte clients. The program is also capable of rewriting the local and remote MAC & IP
 * so that the packets are properly replayed when used on live networks. The current state of the
 * program is that it takes in a pcap file on command line and writes a new file called
 * "newfile.pcap" in which the MACs/IPs/PORTs are adjusted. This file is used thereafter for the
 * rest of the program's calculations and set expectations. Once the program is done,
 * "newfile.pcap" is cleand up.
 *
 * Program Design Overview:
 * Before replaying the packets, the program reads in the pcap file that contains one tcp flow,
 * and takes the SEQ/ACK #s.
 * Based on the number of packets, a struct schedule of events are is set up. Based on
 * the SEQ/ACK numbers read in, the schedule is setup to be relative numbers rather than
 * absolute. This is done by starting with local packets, subtracting the first SEQ (which
 * is that of the first SYN packet) from all the SEQs of the local packets then by subtracting
 * the first remote sequence (which is that of the SYN-ACK packet) from all the local packet's
 * ACKs. After the local side SEQ/ACK numbers are fixed to relative numbers, 'lseq_adjust'
 * the locally generated random number for the SYN packet gets added to all the local SEQs (if the
 * random option is activated) to adjust the schedule to absolute number configuration. Then doing
 * the remote side is similar except we only fix the remote ACKs based on our locally generated
 * random number because we do not yet know the remote random number of the SYN-ACK packet. This
 * means that at this point the entire schedule of local packets and remote packets are set in such
 * a way that the local packets' SEQ's are absolute, but ACKs are relative and the remote packets'
 * SEQ's are relative but ACKs as absolute. Once this is set, the replay starts by sending first
 * SYN packet. If the remote host's acks with the SYN packet_SEQ+1 then we save their remote SEQ
 * and adjust the local ACKs and remote SEQs in the struct schedule to be absolute based this
 * remote SEQ. From this point on forward, we know or 'expect' what the remote host's ACKs and SEQs
 * are exactly. If the remote host responds correctly as we expect (checking the schedule position
 * expectation as packets are received) then we proceed in the schedule whether the next event is
 * to send a local packet or wait for a remote packet to arrive.
 */
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::{thread, time};

use log::info;
use pcap::Capture;
use pnet::datalink;
use pnet::ipnetwork::IpNetwork;
use pnet::packet::tcp::TcpFlags;
use pnet::packet::{ethernet, ipv4, tcp, MutablePacket, Packet};
pub use pnet::util::MacAddr;
use rand::{thread_rng, Rng};

static TMP_FILE: &str = "newfile.pcap";

pub fn replay_init() {
    env_logger::init();
}

pub fn replay<P>(
    interface: &str,
    file: P,
    rand: bool,
    ip_dst: Ipv4Addr,
    mac_dst: MacAddr,
    port_src: u16,
) -> Option<Vec<u8>>
where
    P: AsRef<Path>,
{
    // get local ip and mac
    let (myip, mymac) = get_ip_and_mac(interface);
    info!("local mac: {:?}, local ip {:?}", mymac, myip);

    rewrite(ip_dst, mac_dst, myip, mymac, file, port_src);

    let mut sched_list = setup_sched().expect("failed to setup schedule");

    let exp_rseq = sched_list[1].exp_rseq; // get expected remote sequence number (as basis for relative counting)
    relative_sched(&mut sched_list, exp_rseq, rand);
    info!("Packets Scheduled");

    let cap_inactive = Capture::from_device(interface);
    // immediat_mode is needed (https://github.com/the-tcpdump-group/libpcap/issues/572)
    let mut cap_active = cap_inactive.unwrap().immediate_mode(true).open().unwrap();

    // === Sending First Packet ===
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
    let mut syn_ack_encountered = false;
    let mut missing_syn_ack_counter = 0;
    let mut result = None;

    // === Packet Iteration Loop ===
    while sched_index < sched_list.len() {
        // info!("idx: {}", sched_index);

        let cur_sched = &mut sched_list[sched_index];
        match cur_sched.remote_or_local {
            SchedType::Local => {
                // === Send Packet ===
                let curr_lack = cur_sched.curr_lack;
                match cur_sched.packet {
                    Some(ref mut buf) => {
                        adjust_ack(buf, curr_lack);
                        fix_checksums(
                            buf,
                            cur_sched.ip_checksum_correct,
                            cur_sched.tcp_checksum_correct,
                        );
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
                                        if port_src == tcp.get_destination() {
                                            // SYN ACK
                                            if tcp.get_flags() == TcpFlags::SYN | TcpFlags::ACK {
                                                syn_ack_encountered = true;
                                                let initial_rseq = tcp.get_sequence();
                                                info!(
                                                    "Received Remote Packet...............   {}",
                                                    sched_index + 1
                                                );
                                                info!("Remote Packet Expectation met.");
                                                info!("Proceeding in replay....");
                                                info!("Remote Sequence number: {}", initial_rseq);
                                                // make schedule absolute based on received seq
                                                sched_list[1].exp_rseq = sched_list[1]
                                                    .exp_rseq
                                                    .wrapping_add(initial_rseq);
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
                                            if syn_ack_encountered {
                                                info!(">Received a Remote Packet");
                                                info!(">>Checking Expectations");

                                                // Handle Remote Packet Loss

                                                // No Packet Loss... Proceed Normally
                                                if tcp.get_sequence() == cur_sched.exp_rseq
                                                    && tcp.get_acknowledgement()
                                                        == cur_sched.exp_rack
                                                {
                                                    info!("Received Remote Packet (as expected)");
                                                    if (cur_sched.exp_flags & TcpFlags::FIN) > 0 {
                                                        // if FIN is expected in file we want to
                                                        // interpret wait for a push
                                                        if (tcp.get_flags() & TcpFlags::PSH) > 0 {
                                                            result = Some(tcp.payload().to_vec());
                                                            // if next acknowlegement
                                                            sched_list[sched_index + 1]
                                                                .curr_lack +=
                                                                tcp.payload().len() as u32;
                                                            // Essential fix! Wait to prevent the last
                                                            // ACK from being sent ahead of time!
                                                            thread::sleep(
                                                                time::Duration::from_millis(100),
                                                            );
                                                            sched_index += 1;
                                                        }
                                                    } else {
                                                        sched_index += 1;
                                                    }
                                                } else {
                                                    // dbg!(cur_sched.exp_rseq);
                                                    // dbg!(cur_sched.exp_rack);
                                                    info!("{:?},{:?}", tcp, ipv4);
                                                }
                                            } else {
                                                if missing_syn_ack_counter > 3 {
                                                    return None;
                                                }
                                                info!("watiting for SYN ACK");
                                                missing_syn_ack_counter += 1;
                                            }
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
    match fs::remove_file("newfile.pcap") {
        Ok(()) => info!("newfile has been cleaned up"),
        Err(e) => info!("{}", e),
    }
    result
}

/// This method take a pcap file filters out only the tcp packets and adjusts MAC/IP/PORT to the
/// provided information. In addition to that the checksums are fixed if they have been correct
/// before and the resulting packets are written to a new file "newfile.pcap"
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
    // filter out only tcp
    if let Err(e) = reader.filter("tcp", true) {
        eprintln!("{:?}", e);
        panic!("Error applying filter to input file")
    }

    // prepare saving to file
    let save = Capture::dead(pcap::Linktype::ETHERNET).unwrap();
    let mut savefile = save.savefile(TMP_FILE);

    // loop over tcp packets
    while let Ok(packet) = reader.next() {
        let mut ip_checksum_correct = false;
        let mut tcp_checksum_correct = false;
        let mut local = false;
        let mut remote = false;
        let mut test = Vec::new();
        test.extend_from_slice(packet.data);
        match ethernet::MutableEthernetPacket::new(&mut test) {
            Some(mut eth) => {
                match ipv4::MutableIpv4Packet::new(eth.payload_mut()) {
                    Some(mut ipv4) => {
                        let sip = ipv4.get_source();
                        let dip = ipv4.get_destination();
                        if ipv4.get_checksum() == ipv4::checksum(&ipv4.to_immutable()) {
                            ip_checksum_correct = true;
                        }
                        match tcp::MutableTcpPacket::new(ipv4.payload_mut()) {
                            Some(mut tcp) => {
                                // Determine local/remote
                                if tcp.get_flags() == tcp::TcpFlags::SYN {
                                    syn_encountered = true;
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
                                if local && remote {
                                    panic!("same ip and port combination for local and remote")
                                }

                                if syn_encountered {
                                    if tcp.get_checksum()
                                        == tcp::ipv4_checksum(&tcp.to_immutable(), &sip, &dip)
                                    {
                                        tcp_checksum_correct = true;
                                    };
                                    // Set Port
                                    if local {
                                        tcp.set_source(new_src_port);
                                    }
                                    if remote {
                                        tcp.set_destination(new_src_port);
                                    }

                                    // Fix checksum TCP
                                    if tcp_checksum_correct {
                                        tcp.set_checksum(tcp::ipv4_checksum(
                                            &tcp.to_immutable(),
                                            &myip,
                                            &new_remoteip,
                                        ));
                                    }
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
                        if ip_checksum_correct {
                            ipv4.set_checksum(ipv4::checksum(&ipv4.to_immutable()));
                        };
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
    ip_checksum_correct: bool,
    tcp_checksum_correct: bool,
}

impl Sched {
    fn new(ip_checksum_correct: bool, tcp_checksum_correct: bool) -> Sched {
        Sched {
            curr_lseq: 0,
            curr_lack: 0,
            exp_rseq: 0,
            exp_rack: 0,
            exp_flags: 0,
            remote_or_local: SchedType::Local,
            packet: None,
            ip_checksum_correct,
            tcp_checksum_correct,
        }
    }
}

/// Create a list of Packets Scheduled to send
fn setup_sched() -> Option<Vec<Sched>> {
    // read file altered in rewrite()
    let mut cap_file = Capture::from_file(TMP_FILE).unwrap();

    // local port and ip (to be determined on the first SYN packet)
    let mut local_ip = None;
    let mut local_port = None;

    let mut sched_list = vec![];
    while let Ok(packet) = cap_file.next() {
        // indication if packet is send by local or remote
        let mut ip_checksum_correct = false;
        let mut tcp_checksum_correct = false;
        let mut local = false;
        let mut remote = false;
        match ethernet::EthernetPacket::new(&packet) {
            Some(eth) => match ipv4::Ipv4Packet::new(eth.payload()) {
                Some(ipv4) => {
                    // get src and dst pi for later
                    let sip = ipv4.get_source();
                    let dip = ipv4.get_destination();
                    if ipv4.get_checksum() == ipv4::checksum(&ipv4.to_immutable()) {
                        ip_checksum_correct = true;
                    }
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

                            if tcp.get_checksum()
                                == tcp::ipv4_checksum(&tcp.to_immutable(), &sip, &dip)
                            {
                                tcp_checksum_correct = true;
                            };
                            let mut sched = Sched::new(ip_checksum_correct, tcp_checksum_correct);
                            // FIRST PACKET (SYN)
                            if tcp.get_flags() == TcpFlags::SYN {
                                sched.remote_or_local = SchedType::Local;
                                sched.curr_lseq = tcp.get_sequence();
                                sched.packet = Some(eth.packet().into());
                                sched_list.push(sched);
                            }
                            // LOCAL
                            else if local {
                                sched.remote_or_local = SchedType::Local;

                                sched.curr_lseq = tcp.get_sequence();
                                sched.curr_lack = tcp.get_acknowledgement();
                                sched.exp_rseq = sched_list.last()?.exp_rseq;
                                sched.exp_rack = sched_list.last()?.exp_rack;
                                sched.packet = Some(eth.packet().into());
                                sched_list.push(sched);
                            }
                            // REMOTE
                            else if remote {
                                sched.remote_or_local = SchedType::Remote;

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

/// Adjust schedule to be based on new initial seqence numbers. The local side will be based on a
/// randomly generated value and the remote side will be made based on 0 for the moment (realtive)
/// until the initial sequence number of the remote will be received.
fn relative_sched(sched_list: &mut Vec<Sched>, first_rseq: u32, rand: bool) {
    info!("relative_sched");
    let first_lseq = sched_list.first().unwrap().curr_lseq;

    let lseq_adjust: u32;
    if rand {
        info!("Generate random local SEQ");
        lseq_adjust = thread_rng().gen();
    } else {
        lseq_adjust = first_lseq;
    }
    info!("Local SEQ: {}", lseq_adjust);
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
                        fix_checksums(buf, sched.ip_checksum_correct, sched.tcp_checksum_correct);
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
fn fix_checksums(buf: &mut [u8], fix_ip: bool, fix_tcp: bool) {
    match ethernet::MutableEthernetPacket::new(buf) {
        Some(mut eth) => match ipv4::MutableIpv4Packet::new(eth.payload_mut()) {
            Some(mut ipv4) => {
                let sip = ipv4.get_source();
                let dip = ipv4.get_destination();
                match tcp::MutableTcpPacket::new(ipv4.payload_mut()) {
                    Some(mut tcp) => {
                        if fix_tcp {
                            tcp.set_checksum(tcp::ipv4_checksum(&tcp.to_immutable(), &sip, &dip));
                        }
                    }
                    None => {}
                }
                if fix_ip {
                    ipv4.set_checksum(ipv4::checksum(&ipv4.to_immutable()));
                }
            }
            None => {}
        },
        None => {}
    };
}

/// Returns tuple (Ipv4, Mac) that was determined using pnet::datalink::interfaces()
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
