use std::net::Ipv4Addr;
use tcpreplay::replay;

use clap::Parser;
use pnet::util::MacAddr;
use std::env;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// name of the interface that is doing the replay
    #[clap(short = 'I', long)]
    interface: String,

    /// pcap file to replay
    #[clap(short, long)]
    file: String,

    /// ipv4 address of the target system
    #[clap(short = 'i', long)]
    ip_dst: Ipv4Addr,

    /// mac address of the target system
    #[clap(short, long)]
    mac_dst: MacAddr,

    /// local port to be used
    #[clap(short, long)]
    port_src: u16,

    /// print additional logging information
    #[clap(short, long)]
    verbose: bool,

    /// use random sequence nummbers
    #[clap(short, long)]
    rand: bool,
}

fn main() {
    // arg parsing
    let args = Args::parse();
    if args.verbose {
        println!("verbose");
        env::set_var("RUST_LOG", "info");
    }
    replay(
        args.interface.as_str(),
        args.file.as_str(),
        args.rand,
        args.ip_dst,
        args.mac_dst,
        args.port_src,
    );
}
