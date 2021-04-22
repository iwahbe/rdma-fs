use clap::{App, Arg, SubCommand};
use env_logger;
use fuser::spawn_mount;
use rdma_fuse::{remote_server, LocalMount, RDMAConnection, RDMAFs};
use std::str::FromStr;
use std::{io, io::stdin, path::PathBuf};

const DEFAULT_PORT: &str = "127.0.0.1:8080";

fn main() -> io::Result<()> {
    env_logger::init();
    let ip_arg = Arg::with_name("ip")
        .short("p")
        .long("ip")
        .takes_value(true)
        .help("What ip (Tcp) address threads will exchange RDMA enpoints over.")
        .validator(|s| match std::net::SocketAddr::from_str(&s) {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("{}, value should be formated as 127.0.0.1:8000", e)),
        });
    let matches = App::new("Passthrough FS")
        .version("0.1")
        .author("Ian wahbe")
        .subcommand(
            SubCommand::with_name("local")
                .about(
                    "Mount a local filesystem, mirroring another point on the current file system",
                )
                .arg(
                    Arg::with_name("mount at")
                        .index(1)
                        .required(true)
                        .help("The empty directory on which to mount the virtual FS"),
                )
                .arg(
                    Arg::with_name("mount to")
                        .index(2)
                        .required(true)
                        .help("The point on the host filesystem to mirror"),
                ),
        )
        .subcommand(
            SubCommand::with_name("test")
                .about(
                    "Run a test, confirming that RDMA exists, and that a connection can be formed",
                )
                .arg(
                    Arg::with_name("sender")
                        .help("This thread will send an rdma message.")
                        .long("sender")
                        .takes_value(false)
                        .conflicts_with("receiver"),
                )
                .arg(
                    Arg::with_name("receiver")
                        .help("This thread will recieve an rdma message.")
                        .long("receiver")
                        .takes_value(false)
                        .conflicts_with("sender"),
                )
                .arg(ip_arg.clone()),
        )
        .subcommand(
            SubCommand::with_name("remote")
                .about("Facilitate file system mirroring over RDMA")
                .arg(
                    Arg::with_name("client")
                        .help("Provide the local file system, talking to a remote host to get data")
                        .long("client")
                        .takes_value(false)
                        .conflicts_with("host"),
                )
                .arg(
                    Arg::with_name("host")
                        .help("Provides the remote end of an RDMA file sytem.")
                        .long("host")
                        .takes_value(true)
                        .conflicts_with("client"),
                )
                .arg(ip_arg),
        )
        .get_matches();
    if let Some(matches) = &matches.subcommand_matches("test") {
        let port = std::net::SocketAddr::from_str(matches.value_of("port").unwrap_or(DEFAULT_PORT))
            .unwrap();
        if matches.is_present("sender") {
            std::thread::sleep(std::time::Duration::from_millis(50));
            let mut socket = std::net::TcpStream::connect(&port)?;
            let r = test_rdma(true, &mut socket);
            match &r {
                Ok(_) => println!("RDMA sent!"),
                Err(e) => {
                    println!("Send failed: {}", e);
                    // Exit will leak memory. This should not matter.
                    std::process::exit(1)
                }
            }
            return r;
        } else if matches.is_present("receiver") {
            let mut socket = std::net::TcpListener::bind(&port)?.accept()?.0;
            let r = test_rdma(false, &mut socket);
            match &r {
                Ok(_) => println!("RDMA received!"),
                Err(e) => {
                    println!("Recieve failed: {}", e);
                    std::process::exit(1)
                }
            }
            return r;
        } else {
            let sender = std::process::Command::new(std::env::args().next().unwrap())
                .arg("test")
                .arg("--sender")
                .spawn()?;
            let reciever = std::process::Command::new(std::env::args().next().unwrap())
                .arg("test")
                .arg("--receiver")
                .spawn()?;
            let sender = sender.wait_with_output()?;
            let reciever = reciever.wait_with_output()?;
            if sender.status.success() && reciever.status.success() {
                return Ok(());
            } else {
                std::process::exit(1);
            }
        }
    }

    if let Some(matches) = &matches.subcommand_matches("local") {
        let mountpoint = matches
            .value_of("mount at")
            .expect("Clap ensures this is non-empty");
        let mount_reflect = matches.value_of("mount to").expect("Mount failed");
        let _backround = spawn_mount(LocalMount::new(mount_reflect), &mountpoint, &[]).unwrap();
        let mut s = String::new();
        println!("Return on input");
        stdin().read_line(&mut s).expect("Failed to read input");
    }

    if let Some(matches) = &matches.subcommand_matches("remote") {
        let port = std::net::SocketAddr::from_str(matches.value_of("port").unwrap_or(DEFAULT_PORT))
            .unwrap();
        if let Some(mountpoint) = matches
            .value_of_lossy("host")
            .map(|s| PathBuf::from_str(&s).unwrap())
        {
            let con = std::net::TcpStream::connect(&port)?;
            let mut con = RDMAConnection::new(1, con)?;
            remote_server(mountpoint, &mut con)?;
        } else {
            let con = std::net::TcpListener::bind(&port)?.accept()?.0;
            let mountpoint = matches
                .value_of_lossy("client")
                .map(|s| PathBuf::from_str(&s).unwrap())
                .unwrap();
            // We are the client
            let _backround = spawn_mount(RDMAFs::new(con)?, mountpoint, &[]).unwrap();
            let mut s = String::new();
            println!("Return on input");
            stdin().read_line(&mut s).expect("Failed to read input");
        }
    }
    Ok(())
}

/// Initiates a rdma connection as either a sender or reciever.
///
/// Communicates an enpoint across `port`, and either sends or receives based on
/// `sender`.
fn test_rdma(sender: bool, port: &mut std::net::TcpStream) -> io::Result<()> {
    let mut con: RDMAConnection<usize> = RDMAConnection::new(1, port)?;
    if sender {
        con[0] = 42;
        con.send()?;
    } else {
        con.recv()?;
        assert_eq!(42, con[0]);
    }
    Ok(())
}
