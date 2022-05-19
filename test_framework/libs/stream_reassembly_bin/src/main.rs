use std::path::PathBuf;
use stream_reassembly::{self, PcapReassembler};

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
        let mut reassembler = PcapReassembler::read_file(config_path, cli.filter.as_deref());

        // print one direction
        if let Some(stream_data) = reassembler.next() {
            print!("{}", String::from_utf8_lossy(&stream_data.1))
        }
        // print the other direction
        if let Some(stream_data) = reassembler.next() {
            print!("{}", String::from_utf8_lossy(&stream_data.1))
        }
    }
}
