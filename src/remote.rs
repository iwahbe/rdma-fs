use fuser::*;
use fuser::{Filesystem, KernelConfig, Request};
use libc::{c_int, statfs, ENOSYS, EREMOTEIO};
use std::{
    collections::HashMap,
    ffi::OsString,
    fs,
    io::{self, Read, Write},
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::PathBuf,
    sync::{atomic::AtomicBool, Arc},
};

use crate::file::{FileBuilder, OpenFile};
use crate::RDMAConnection;
use crate::{Fh, Ino};

use serde::{Deserialize, Serialize};

//TODO: I need a buffered writer for this.
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
enum Message {
    Exit,
    Startup {
        server: bool,
    },
    Null,
    Lookup {
        parent: Ino,
        name: OsString,
        attr: FileAttr,
        generation: u64,
    },
}

impl Default for Message {
    fn default() -> Self {
        Message::Null
    }
}

pub(crate) static EXIT: AtomicBool = AtomicBool::new(false);

/// A blocking call to the main event loop of the RDMA server.
pub fn remote_server(root: PathBuf, connection: &mut RDMAConnection<Message>) -> io::Result<()> {
    connection[0] = Message::Startup { server: true };
    connection.send().unwrap();
    connection.recv().unwrap();
    assert!(Message::Startup { server: false } == connection[0]);
    println!("Handshake with the server completed");

    let mut data = LocalData::new(root);
    loop {
        if EXIT.load(std::sync::atomic::Ordering::Relaxed) {
            eprintln!("Exiting server");
            connection[0] = Message::Exit;
            connection.send().unwrap();
            return Ok(());
        }

        connection.recv().unwrap();

        match connection[0] {
            Message::Exit => {
                println!("Recieved exit command. Goodbye!");
                return Ok(());
            }
            Message::Startup { server: _ } => {
                println!("Recieved unexpected startup command.");
            }
            Message::Null => {}
            Message::Lookup {
                parrent,
                name,
                attr,
                generation,
            } => {
                unimplemented!()
            }
        }
    }
}

pub struct RDMAFs {
    connection: RDMAConnection<Message>,
}

/// Stores the data necessary for acting like a file system.
pub struct LocalData {
    /// Where the root of `Mount` is located in the host file system.
    root: PathBuf,
    /// The ino of the root of the reflected file system.
    root_ino: Ino,
    ino_paths: HashMap<Ino, PathBuf>,
    open_files: HashMap<Fh, OpenFile>,
}

impl LocalData {
    pub fn new(root: PathBuf) -> Self {
        let root = root.canonicalize().unwrap();
        let root_data = fs::metadata(&root).unwrap();
        let root_ino = root_data.ino();
        let ino_paths: HashMap<Ino, PathBuf> = std::iter::once((root_ino, root.clone())).collect();
        Self {
            root,
            root_ino,
            ino_paths,
            open_files: HashMap::new(),
        }
    }
}

impl RDMAFs {
    pub fn new<W>(connection: W) -> io::Result<Self>
    where
        W: Read + Write,
    {
        Ok(Self {
            connection: RDMAConnection::new(1, connection)?,
        })
    }
}

impl Filesystem for RDMAFs {
    fn init(&mut self, _req: &Request<'_>, _config: &mut KernelConfig) -> Result<(), c_int> {
        // TODO: tune kernal with max read and write
        self.connection
            .recv()
            .map_err(|e| e.raw_os_error().unwrap_or(EREMOTEIO))?;
        assert!(self.connection[0] == Message::Startup { server: true });
        eprintln!("Received server send");
        self.connection[0] = Message::Startup { server: false };
        self.connection
            .send()
            .map_err(|e| e.raw_os_error().unwrap_or(EREMOTEIO))?;
        Ok(())
    }

    fn destroy(&mut self, _req: &Request<'_>) {
        self.connection[0] = Message::Exit;
        self.connection.send().unwrap();
    }

    fn lookup(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        reply: ReplyEntry,
    ) {
        self.connection[0] = Message::Lookup {
            parent,
            name: name.clone(),
            attr: FileAttr::default(),
            generation: 0,
        };
        self.connection
            .send()
            .map_err(|e| e.raw_os_error().unwrap_or(EREMOTEIO))?;
        if let Message::Lookup {
            parent,
            name,
            attr,
            generation,
        } = self.connection[0]
        {
            reply.entry(&std::time::Duration::ZERO, &(&attr).into(), generation);
        } else {
            panic!("Expected lookup");
        }
    }

    fn forget(&mut self, _req: &Request<'_>, _ino: u64, _nlookup: u64) {}

    fn getattr(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyAttr) {
        reply.error(ENOSYS);
    }

    fn setattr(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        _size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<std::time::SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<std::time::SystemTime>,
        _chgtime: Option<std::time::SystemTime>,
        _bkuptime: Option<std::time::SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        reply.error(ENOSYS);
    }

    fn readlink(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyData) {
        reply.error(ENOSYS);
    }

    fn mknod(
        &mut self,
        _req: &Request<'_>,
        _parent: u64,
        _name: &std::ffi::OsStr,
        _mode: u32,
        _umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        reply.error(ENOSYS);
    }

    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        _parent: u64,
        _name: &std::ffi::OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        reply.error(ENOSYS);
    }

    fn unlink(
        &mut self,
        _req: &Request<'_>,
        _parent: u64,
        _name: &std::ffi::OsStr,
        reply: ReplyEmpty,
    ) {
        reply.error(ENOSYS);
    }

    fn rmdir(
        &mut self,
        _req: &Request<'_>,
        _parent: u64,
        _name: &std::ffi::OsStr,
        reply: ReplyEmpty,
    ) {
        reply.error(ENOSYS);
    }

    fn symlink(
        &mut self,
        _req: &Request<'_>,
        _parent: u64,
        _name: &std::ffi::OsStr,
        _link: &std::path::Path,
        reply: ReplyEntry,
    ) {
        reply.error(ENOSYS);
    }

    fn rename(
        &mut self,
        _req: &Request<'_>,
        _parent: u64,
        _name: &std::ffi::OsStr,
        _newparent: u64,
        _newname: &std::ffi::OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        reply.error(ENOSYS);
    }

    fn link(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _newparent: u64,
        _newname: &std::ffi::OsStr,
        reply: ReplyEntry,
    ) {
        reply.error(ENOSYS);
    }

    fn open(&mut self, _req: &Request<'_>, _ino: u64, _flags: i32, reply: ReplyOpen) {
        reply.opened(0, 0);
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _offset: i64,
        _size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        reply.error(ENOSYS);
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _offset: i64,
        _data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        reply.error(ENOSYS);
    }

    fn flush(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _lock_owner: u64,
        reply: ReplyEmpty,
    ) {
        reply.error(ENOSYS);
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn fsync(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        reply.error(ENOSYS);
    }

    fn opendir(&mut self, _req: &Request<'_>, _ino: u64, _flags: i32, reply: ReplyOpen) {
        reply.opened(0, 0);
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _offset: i64,
        reply: ReplyDirectory,
    ) {
        reply.error(ENOSYS);
    }

    fn readdirplus(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _offset: i64,
        reply: ReplyDirectoryPlus,
    ) {
        reply.error(ENOSYS);
    }

    fn releasedir(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _flags: i32,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn fsyncdir(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        reply.error(ENOSYS);
    }

    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyStatfs) {
        reply.statfs(0, 0, 0, 0, 0, 512, 255, 0);
    }

    fn setxattr(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _name: &std::ffi::OsStr,
        _value: &[u8],
        _flags: i32,
        _position: u32,
        reply: ReplyEmpty,
    ) {
        reply.error(ENOSYS);
    }

    fn getxattr(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _name: &std::ffi::OsStr,
        _size: u32,
        reply: ReplyXattr,
    ) {
        reply.error(ENOSYS);
    }

    fn listxattr(&mut self, _req: &Request<'_>, _ino: u64, _size: u32, reply: ReplyXattr) {
        reply.error(ENOSYS);
    }

    fn removexattr(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _name: &std::ffi::OsStr,
        reply: ReplyEmpty,
    ) {
        reply.error(ENOSYS);
    }

    fn access(&mut self, _req: &Request<'_>, _ino: u64, _mask: i32, reply: ReplyEmpty) {
        reply.error(ENOSYS);
    }

    fn create(
        &mut self,
        _req: &Request<'_>,
        _parent: u64,
        _name: &std::ffi::OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        reply.error(ENOSYS);
    }

    fn getlk(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _lock_owner: u64,
        _start: u64,
        _end: u64,
        _typ: i32,
        _pid: u32,
        reply: ReplyLock,
    ) {
        reply.error(ENOSYS);
    }

    fn setlk(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _lock_owner: u64,
        _start: u64,
        _end: u64,
        _typ: i32,
        _pid: u32,
        _sleep: bool,
        reply: ReplyEmpty,
    ) {
        reply.error(ENOSYS);
    }

    fn bmap(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _blocksize: u32,
        _idx: u64,
        reply: ReplyBmap,
    ) {
        reply.error(ENOSYS);
    }

    fn ioctl(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _flags: u32,
        _cmd: u32,
        _in_data: &[u8],
        _out_size: u32,
        reply: ReplyIoctl,
    ) {
        reply.error(ENOSYS);
    }

    fn fallocate(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _offset: i64,
        _length: i64,
        _mode: i32,
        reply: ReplyEmpty,
    ) {
        reply.error(ENOSYS);
    }

    fn lseek(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _offset: i64,
        _whence: i32,
        reply: ReplyLseek,
    ) {
        reply.error(ENOSYS);
    }

    fn copy_file_range(
        &mut self,
        _req: &Request<'_>,
        _ino_in: u64,
        _fh_in: u64,
        _offset_in: i64,
        _ino_out: u64,
        _fh_out: u64,
        _offset_out: i64,
        _len: u64,
        _flags: u32,
        reply: ReplyWrite,
    ) {
        reply.error(ENOSYS);
    }
}
