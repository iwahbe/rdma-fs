use clap::{App, Arg, SubCommand};
use env_logger;
use fuser::spawn_mount;
use rdma_fuse::LocalMount;
use std::{io, io::stdin};

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
                .about("Run a test, confirming that RDMA exists")
                .arg(
                    Arg::with_name("sender")
                        .long("sender")
                        .takes_value(false)
                        .conflicts_with("receiver"),
                )
                .arg(
                    Arg::with_name("receiver")
                        .long("receiver")
                        .takes_value(false)
                        .conflicts_with("sender"),
                ),
        )
        .get_matches();
    if let Some(matches) = &matches.subcommand_matches("test") {
        if matches.is_present("sender") {
            let r = test_rdma(true);
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
            let r = test_rdma(false);
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

fn test_rdma(sender: bool) -> io::Result<()> {
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
    while !sent || !received {
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
                    assert!(!sent);
                    sent = true;
                    println!("sent");
                }
                2 => {
                    assert!(!received);
                    received = true;
                    assert_eq!(mr[0], 0x42);
                    println!("received");
                }
                _ => unreachable!(),
            }
        }
    }

    Ok(())
}
