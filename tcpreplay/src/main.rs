use std::net::Ipv4Addr;
use tcpreplay::replay;

use clap::Parser;
use pnet::util::MacAddr;
use std::env;

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
    )
}
