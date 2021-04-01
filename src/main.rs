use bincode;
use clap::{App, Arg, SubCommand};
use env_logger;
use fuser::spawn_mount;
use rdma_fuse::LocalMount;
use std::str::FromStr;
use std::{
    io,
    io::{stdin, Write},
};

fn main() -> io::Result<()> {
    env_logger::init();
    let matches = App::new("Passthrough FS")
        .version("0.1")
        .author("Ian wahbe")
        .subcommand(
            SubCommand::with_name("local")
                .about("Mount a local filesystem")
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
                .arg(
                    Arg::with_name("ip")
                        .short("p")
                        .long("ip")
                        .takes_value(true)
                        .help("What ip (Tcp) address threads will exchange RDMA enpoints over."),
                ),
        )
        .get_matches();
    if let Some(matches) = &matches.subcommand_matches("test") {
        let port =
            std::net::SocketAddr::from_str(matches.value_of("port").unwrap_or("127.0.0.1:8080"))
                .unwrap();
        if matches.is_present("sender") {
            std::thread::sleep(std::time::Duration::from_millis(50));
            let socket = std::net::TcpStream::connect(&port)?;
            let r = test_rdma(true, socket);
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
            let socket = std::net::TcpListener::bind(&port)?.accept()?.0;
            let r = test_rdma(false, socket);
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
    Ok(())
}

/// Initiates a rdma connection as either a sender or reciever.
///
/// Communicates an enpoint across `port`, and either sends or receives based on
/// `sender`.
fn test_rdma(sender: bool, mut port: std::net::TcpStream) -> io::Result<()> {
    let ctx = ibverbs::devices()?
        .iter()
        .next()
        .ok_or(io::Error::from(io::ErrorKind::NotFound))?
        .open()?;

    let cq = ctx.create_cq(16, 0)?;
    let pd = ctx
        .alloc_pd()
        .map_err(|_| io::Error::from(io::ErrorKind::AddrNotAvailable))?;

    let qp_builder = pd
        .create_qp(&cq, &cq, ibverbs::ibv_qp_type::IBV_QPT_RC)
        .build()?;

    let endpoint = qp_builder.endpoint();
    let encode: Vec<u8> = bincode::serialize(&endpoint).unwrap();
    port.write(&encode)?;
    let endpoint: ibverbs::QueuePairEndpoint = bincode::deserialize_from(&mut port).unwrap();
    let mut qp = qp_builder.handshake(endpoint)?;

    let mut mr = pd.allocate::<u64>(2)?;
    mr[1] = 0x42;

    if sender {
        unsafe { qp.post_send(&mut mr, 1.., 1) }?;
    } else {
        unsafe { qp.post_receive(&mut mr, ..1, 2) }?;
    }

    let mut sent = false;
    let mut received = false;
    let mut completions = [ibverbs::ibv_wc::default(); 16];
    while !sent && !received {
        let completed = cq
            .poll(&mut completions[..])
            .map_err(|_| io::Error::from(io::ErrorKind::Interrupted))?;
        if completed.is_empty() {
            continue;
        }
        assert!(completed.len() <= 2);
        for wr in completed {
            match wr.wr_id() {
                1 => {
                    assert!(!sent && sender);
                    sent = true;
                }
                2 => {
                    assert!(!received && !sender);
                    received = true;
                    assert_eq!(mr[0], 0x42);
                }
                _ => unreachable!(),
            }
        }
    }

    Ok(())
}
