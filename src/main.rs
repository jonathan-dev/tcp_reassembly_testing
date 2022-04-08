mod macaddr;

use clap::{Parser, Subcommand};
use glob::glob;
use macaddr::MacAddr;
use std::{
    net::Ipv4Addr,
    os::unix::prelude::ExitStatusExt,
    path::PathBuf,
    process::Command,
    process::{self, ExitStatus},
};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Cli {
    #[clap(short, long)]
    no_error: bool,
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Adds files to myapp
    Install,
    Clean,
    Run,
    TestOs {
        #[clap(short, long)]
        ip: Ipv4Addr,
        #[clap(short, long)]
        mac: MacAddr,
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Clean => {
            Command::new("sh")
                .arg(PathBuf::from("./attacks/clean.sh"))
                .output()
                .expect("problem cleaning attacks");
            for bin in glob("./bins_to_test/*").expect("Failed to read bin_to_test glob") {
                match bin {
                    Ok(bin) => {
                        println!("{}", bin.display());
                        Command::new("rm")
                            .arg("-rf")
                            .arg(bin)
                            .output()
                            .expect("error removin bins in bins_to_test");
                    }
                    Err(e) => println!("{}", e),
                }
            }
            for lib in glob("./libs/*").expect("Failed to read lib glob") {
                match lib {
                    Ok(lib) => {
                        println!("{}", lib.display());
                        Command::new("sh")
                            .arg(lib.join("clean.sh"))
                            .output()
                            .expect(format!("{}", lib.join("install.sh").display()).as_str());
                    }
                    Err(e) => println!("{}", e),
                }
            }
        }
        Commands::Install => {
            Command::new("sh")
                .arg(PathBuf::from("./attacks/install.sh"))
                .output()
                .expect("problem generating attacks");
            for lib in glob("./libs/*").expect("Failed to read lib glob") {
                match lib {
                    Ok(lib) => {
                        println!("{}", lib.display());
                        let output = Command::new("sh")
                            .arg(lib.join("install.sh"))
                            .output()
                            .expect(format!("{}", lib.join("install.sh").display()).as_str());
                        println!("{:?}", output);
                    }
                    Err(e) => println!("{}", e),
                }
            }
        }

        Commands::Run => {
            // check dir bins_to_test empty/exists
            let bin_dir_empty = PathBuf::from("./bins_to_test/")
                .read_dir()
                .map(|mut i| i.next().is_none())
                .unwrap_or(false);
            if !PathBuf::from("./bins_to_test/").exists() || bin_dir_empty {
                eprintln!(
                    "No binaries have been istalled yet consider running the install subcommand."
                );
                process::exit(1);
            }
            // find pcap files
            for entry in glob("./attacks/*.pcap").expect("Failes to read glob pattern") {
                match entry {
                    Ok(attack_path) => {
                        println!("==={}===", attack_path.display());
                        for bin_entry in
                            glob("./bins_to_test/*").expect("Failes to read glob pattern")
                        {
                            match bin_entry {
                                Ok(bin) => {
                                    let bin_name = bin.clone();
                                    let mut real_bin = bin;
                                    if real_bin.is_dir() {
                                        let folder_name = real_bin.clone();
                                        real_bin.push(folder_name.file_name().unwrap());
                                    }
                                    let output = Command::new(real_bin)
                                        .args(["-f", attack_path.display().to_string().as_str()])
                                        .output()
                                        .expect("failed to execute process");
                                    if !cli.no_error || output.status == ExitStatus::from_raw(0) {
                                        println!("{:?}, {:?}", output, bin_name);
                                    }
                                }
                                Err(e) => println!("{:?}", e),
                            }
                        }
                    }
                    Err(e) => println!("{:?}", e),
                }
            }
        }
        Commands::TestOs { ip, mac } => {
            println!("{}, {:?}", ip, mac);
            // find pcap files
            for entry in glob("./attacks/*.pcap").expect("Failes to read glob pattern") {
                match entry {
                    Ok(attack_path) => {
                        println!("==={}===", attack_path.display());
                        // TODO: function call
                    }
                    Err(e) => println!("{:?}", e),
                }
            }
        }
    }
}
