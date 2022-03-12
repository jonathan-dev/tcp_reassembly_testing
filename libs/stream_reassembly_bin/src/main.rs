use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;

use stream_reassembly::{
    self,
    reassembler::{FlowKey, Listener},
    PcapReassembler,
};

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

struct MyListener {
    data: HashMap<FlowKey, Vec<u8>>,
}

impl Listener for MyListener {
    fn accept_tcp(&mut self, bytes: Vec<u8>, stream_key: FlowKey) {
        let stream_bytes = self.data.entry(stream_key).or_default();
        for byte in bytes.clone().into_iter() {
            stream_bytes.push(byte);
        }
        print!("{}", String::from_utf8_lossy(&bytes));
    }
}

fn main() {
    let cli = Cli::parse();

    if let Some(config_path) = cli.file.as_deref() {
        // println!("Value for file: {}", config_path.display());
        let l = Rc::new(RefCell::new(MyListener {
            data: HashMap::new(),
        }));
        PcapReassembler::read_file(
            config_path,
            cli.filter.as_deref(),
            Rc::clone(&l) as Rc<RefCell<dyn Listener>>,
        );
    }
}
