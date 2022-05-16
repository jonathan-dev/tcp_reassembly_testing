use clap::{Parser, Subcommand};
use glob::glob;
use std::{
    net::Ipv4Addr,
    os::unix::prelude::ExitStatusExt,
    path::PathBuf,
    process::Command,
    process::{self, ExitStatus},
};
use tcpreplay::replay;
use tcpreplay::replay_init;
use tcpreplay::MacAddr;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate all files (attacks, libs)
    Install,
    /// Remove generated files (attacks, libs)
    Clean,
    /// Run the generated tests in the attacks folder on the compliled libraries in the libs folder
    TestLib {
        /// specify the name of the library to test
        #[clap(short, long)]
        lib: Option<String>,
        /// specify the name of the test to run
        #[clap(short, long)]
        test: Option<String>,
    },
    /// Run the the generated tests in the attacks folder on an live target
    TestOs {
        /// ipv4 address of the target system
        #[clap(short, long)]
        ip: Ipv4Addr,
        /// Mac address of the target system
        #[clap(short, long)]
        mac: MacAddr,
        /// name of the interface to use to connenct to the target system
        #[clap(short = 'I', long)]
        interface: String,
        /// local port to use
        #[clap(short, long)]
        port: u16,
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

        Commands::TestLib { lib, test } => {
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
            let test_name = match test {
                None => "*",
                Some(s) => s,
            };
            let g = glob(&format!("./attacks/{}.pcap", test_name).to_string())
                .expect("Failes to read glob pattern");
            for entry in g {
                match entry {
                    Ok(attack_path) => {
                        println!("==={}===", attack_path.display());
                        if let Some(lib) = lib {
                            let mut bin = PathBuf::from("./bins_to_test");
                            bin.push(lib);
                            run_test_on_bin(PathBuf::from(bin), attack_path.clone());
                        } else {
                            for bin_entry in
                                glob("./bins_to_test/*").expect("Failes to read glob pattern")
                            {
                                match bin_entry {
                                    Ok(bin) => run_test_on_bin(bin, attack_path.clone()),
                                    Err(e) => println!("{:?}", e),
                                }
                            }
                        }
                    }
                    Err(e) => println!("{:?}", e),
                }
            }
        }
        Commands::TestOs {
            ip,
            mac,
            interface,
            port,
        } => {
            println!("{}, {:?}", ip, mac);
            // std::env::set_var("RUST_LOG", "info");
            replay_init();
            // find pcap files
            for entry in glob("./attacks/*.pcap").expect("Failes to read glob pattern") {
                match entry {
                    Ok(attack_path) => {
                        println!("==={}===", attack_path.display());
                        let res = replay(interface, attack_path.clone(), false, *ip, *mac, *port);

                        match res {
                            Some(res) => println!("{}", String::from_utf8_lossy(&res)),

                            None => eprintln!("Error running test {:?} no result", attack_path),
                        }
                    }
                    Err(e) => println!("{:?}", e),
                }
            }
        }
    }
}

fn run_test_on_bin(bin: PathBuf, attack_path: PathBuf) {
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
    if output.status == ExitStatus::from_raw(0) {
        println!(
            "{}, {}, {:?}",
            String::from_utf8_lossy(&output.stdout),
            output.status,
            bin_name
        );
        if !output.stderr.is_empty() {
            println!("{}", String::from_utf8_lossy(&output.stderr));
        }
    } else {
        print!("{:?}", output);
    }
}
