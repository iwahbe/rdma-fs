use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use env_logger;
use fuser::spawn_mount;
use rdma_fuse::{remote_server, LocalMount, RDMAConnection, RDMAFs, RDMA_MESSAGE_BUFFER_SIZE};
use std::{io, io::stdin, net::ToSocketAddrs, path::PathBuf};
use std::{net::TcpStream, str::FromStr};

const DEFAULT_IP: &str = "127.0.0.1:8080";
const IP_COMMAND: &str = "ip";

fn main() -> io::Result<()> {
    env_logger::init();
    let ip_arg = Arg::with_name(IP_COMMAND)
        .short("p")
        .long(IP_COMMAND)
        .takes_value(true)
        .help("What ip (Tcp) address threads will exchange RDMA enpoints over.")
        .validator(|s| match std::net::SocketAddr::from_str(&s) {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("{}, value should be formated as 127.0.0.1:8000", e)),
        });
    let matches = App::new("Passthrough FS")
        .version("0.1")
        .author("Ian wahbe")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(
            SubCommand::with_name("local")
                .about(
                    "Mount a local filesystem, mirroring another point on the current file system",
                )
                .arg(
                    Arg::with_name("rdma")
                        .takes_value(false)
                        .help("Even though this is the same system, use rdma anyway")
                        .long("rdma"),
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
                )
                .arg(ip_arg.clone()),
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
                        .takes_value(true)
                        .conflicts_with("host")
                        .required(true),
                )
                .arg(
                    Arg::with_name("host")
                        .help("Provides the remote end of an RDMA file sytem.")
                        .long("host")
                        .takes_value(true)
                        .conflicts_with("client")
                        .required(true),
                )
                .arg(ip_arg),
        )
        .get_matches();
    if let Some(matches) = matches.subcommand_matches("test") {
        handle_test(matches)?;
    }

    if let Some(matches) = matches.subcommand_matches("local") {
        let mountpoint = matches
            .value_of("mount at")
            .expect("Clap ensures this is non-empty");
        let mount_reflect = matches.value_of("mount to").expect("Mount failed");

        if matches.is_present("rdma") {
            let port = matches.value_of(IP_COMMAND).unwrap_or(DEFAULT_IP);
            // We ape a remote rdma process over the default port
            let mut join = std::process::Command::new(std::env::args().next().unwrap())
                .arg("remote")
                .arg("--client")
                .arg(mountpoint)
                .arg("--ip")
                .arg(port)
                .spawn()?;
            let res = std::process::Command::new(std::env::args().next().unwrap())
                .arg("remote")
                .arg("--host")
                .arg(mount_reflect)
                .arg("--ip")
                .arg(port)
                .spawn()?
                .wait()?;
            let join = join.wait()?;
            std::process::exit(if join.success() && res.success() {
                0
            } else {
                1
            });
        } else {
            // It's all a local process
            let _backround = spawn_mount(LocalMount::new(mount_reflect), &mountpoint, &[]).unwrap();
            let mut s = String::new();
            println!("Return on input");
            stdin().read_line(&mut s).expect("Failed to read input");
        }
    }

    if let Some(matches) = matches.subcommand_matches("remote") {
        handle_remote(matches)?;
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

fn handle_test(matches: &ArgMatches) -> io::Result<()> {
    let port =
        std::net::SocketAddr::from_str(matches.value_of(IP_COMMAND).unwrap_or(DEFAULT_IP)).unwrap();
    if matches.is_present("sender") {
        let mut socket = std::net::TcpStream::connect(&port);
        while socket.is_err() {
            std::thread::sleep(std::time::Duration::from_millis(50));
            socket = std::net::TcpStream::connect(&port);
        }
        let mut socket = socket.unwrap();
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
        let port = matches.value_of(IP_COMMAND).unwrap_or(DEFAULT_IP);
        let sender = std::process::Command::new(std::env::args().next().unwrap())
            .arg("test")
            .arg("--sender")
            .arg("--ip")
            .arg(port)
            .spawn()?;
        let reciever = std::process::Command::new(std::env::args().next().unwrap())
            .arg("test")
            .arg("--receiver")
            .arg("--ip")
            .arg(port)
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

fn connect_port<T>(port: &T) -> io::Result<TcpStream>
where
    T: ToSocketAddrs,
{
    let mut con;
    loop {
        con = std::net::TcpStream::connect(&port);
        let mut timeout = 2;
        match con {
            Ok(_) => break,
            Err(e) => match e.kind() {
                io::ErrorKind::TimedOut => {
                    eprintln!("Connection timed out, retrying");
                }
                io::ErrorKind::ConnectionRefused => {
                    eprintln!("Connection refused: retrying");
                    timeout = 1;
                }
                _ => {
                    eprintln!("Failed to connect: {}", e);
                    return Err(e);
                }
            },
        }
        std::thread::sleep(std::time::Duration::from_secs(timeout));
    }
    con
}

fn handle_remote(matches: &ArgMatches) -> io::Result<()> {
    let port =
        std::net::SocketAddr::from_str(matches.value_of(IP_COMMAND).unwrap_or(DEFAULT_IP)).unwrap();
    if let Some(mountpoint) = matches
        .value_of_lossy("host")
        .map(|s| PathBuf::from_str(&s).unwrap())
    {
        let con = std::net::TcpListener::bind(&port)?.accept()?.0;
        let mut con = RDMAConnection::new(RDMA_MESSAGE_BUFFER_SIZE, con)?;
        remote_server(mountpoint, &mut con)?;
    } else {
        let con = connect_port(&port)?;
        let mountpoint = matches
            .value_of_lossy("client")
            .map(|s| PathBuf::from_str(&s).unwrap())
            .unwrap();
        // We are the client
        let con = RDMAFs::new(con)?;
        let backround = spawn_mount(con, mountpoint, &[]).unwrap();
        let mut s = String::new();
        println!("Return on input");
        stdin().read_line(&mut s).expect("Failed to read input");
        drop(backround);
    }
    Ok(())
}
