use clap::{App, Arg};
use env_logger;
use fuser::spawn_mount;
use rdma_fuse::LocalMount;
use std::io::stdin;

fn main() {
    env_logger::init();
    let matches = App::new("Passthrough FS")
        .version("0.1")
        .author("Ian wahbe")
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
        .get_matches();
    let mountpoint = matches.value_of("mount at").unwrap();
    let mount_reflect = matches.value_of("mount to").unwrap();
    let _backround = spawn_mount(LocalMount::new(mount_reflect), &mountpoint, &[]).unwrap();
    let mut s = String::new();
    println!("Return on input");
    stdin().read_line(&mut s).expect("Failed to read input");
}
