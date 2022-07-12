use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;

use stream_reassembly::{self, reassembler::FlowKey, PcapReassembler};

use clap::Parser;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Sets a custom config file
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    file: Option<PathBuf>,

    #[clap(long, value_name = "FILTER")]
    filter: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    if let Some(config_path) = cli.file.as_deref() {
        // println!("Value for file: {}", config_path.display());
        let key_of_interest = FlowKey {
            src: SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 6001),
            dst: SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 6000),
        };

        let mut reassembler = PcapReassembler::read_file(config_path, cli.filter.as_deref());

        if let Some(stream_data) = reassembler.find(|(key, _, _)| key == &key_of_interest) {
            print!("{}", String::from_utf8_lossy(&stream_data.1))
        }
    }
}
