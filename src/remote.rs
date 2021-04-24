use crate::file::{FileBuilder, OpenFile};
use crate::RDMAConnection;
use crate::{Fh, Ino};
use fuser::*;
use fuser::{Filesystem, KernelConfig, Request};
use libc::{c_int, ENOSYS, EREMOTEIO};
use nix::errno::{errno, Errno};
use std::{
    collections::HashMap,
    convert::TryInto,
    ffi::{CStr, CString, OsStr},
    fs,
    io::{self, Read, Write},
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::PathBuf,
    sync::atomic::AtomicBool,
};

const MAX_FILENAME_LENGTH: usize = 255;

#[derive(Clone, Copy, PartialEq)]
pub enum Message {
    Exit,
    Startup {
        server: bool,
    },
    Null,
    Lookup {
        errno: Option<i32>,
        parent: Ino,
        name: [u8; MAX_FILENAME_LENGTH],
        attr: Option<FileAttr>, //to allow default
        generation: u64,
    },

    GetAttr {
        errno: Option<i32>,
        ino: Ino,
        attr: Option<FileAttr>,
    },
    OpenDir {
        errno: Option<i32>,
        ino: Ino,
        flags: i32,
        fh: Fh,
        open_flags: u32,
    },
    ReadDir {
        ino: Ino,
        fh: Fh,

        // For buffered comminication
        finished: bool,
        errno: Option<i32>,
        buf_ino: Ino,
        offset: i64,
        kind: FileType,
        name: [u8; MAX_FILENAME_LENGTH],
    },

    ReleaseDir {
        fh: Fh,
        errno: Option<i32>,
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
    assert!(
        Message::Startup { server: false } == connection[0],
        "Failed startup handshake (server)"
    );
    println!("Handshake with the server completed");

    let mut data = LocalData::new(root);
    loop {
        if EXIT.load(std::sync::atomic::Ordering::Relaxed) {
            eprintln!("Exiting server");
            connection[0] = Message::Exit;
            connection.send().unwrap();
            return Ok(());
        }

        connection.recv()?;

        match &mut connection[0] {
            Message::Exit => {
                println!("Recieved exit command. Goodbye!");
                return Ok(());
            }
            Message::Startup { server: _ } => {
                println!("Recieved unexpected startup command.");
            }
            Message::Null => {}
            Message::Lookup {
                parent,
                name,
                attr,
                generation,
                errno,
            } => match data.lookup(*parent, name) {
                Ok((fattr, gen)) => {
                    *attr = Some(fattr);
                    *generation = gen;
                }
                Err(e) => *errno = Some(e),
            },
            Message::GetAttr { errno, ino, attr } => match data.getattr(*ino) {
                Ok(k) => {
                    *attr = Some(k);
                    *errno = None;
                }
                Err(e) => {
                    *errno = Some(e);
                    *attr = None;
                }
            },
            Message::OpenDir {
                ino,
                flags,
                fh,
                open_flags,
                errno,
            } => match data.opendir(*ino, *flags) {
                Ok((file_handle, flags)) => {
                    *open_flags = flags;
                    *fh = file_handle;
                    *errno = None;
                }
                Err(e) => *errno = Some(e),
            },
            Message::ReleaseDir { fh, errno } => *errno = data.releasedir(*fh).err(),
            Message::ReadDir {
                ino,
                fh,
                errno,
                buf_ino,
                offset,
                kind,
                name,
                finished,
            } => match data.readdir(*ino, *fh) {
                Ok(Some((r_ino, r_offset, r_kind, r_name))) => {
                    *errno = None;
                    *buf_ino = r_ino;
                    *offset = r_offset;
                    *kind = r_kind;
                    *name = r_name;
                }
                Ok(None) => *finished = true,
                Err(e) => *errno = Some(e),
            },
        }
        connection.send()?;
    }
}

pub struct RDMAFs {
    connection: RDMAConnection<Message>,
    initialized: bool,
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
    fn readdir(
        &mut self,
        ino: u64,
        fh: u64,
    ) -> Result<Option<(Ino, i64, FileType, [u8; MAX_FILENAME_LENGTH])>, i32> {
        Errno::clear(); // Because it's not clear if readdir failed from it's output
        let dir_ent = unsafe { libc::readdir(fh as _) };
        if dir_ent.is_null() {
            use libc::*;
            match errno() {
                EACCES | EBADF | EMFILE | ENFILE | ENOENT | ENOMEM | ENOTDIR => {
                    log::error!(
                        "Encountered error {} reading directory {:?}, fh {:?}",
                        std::io::Error::from_raw_os_error(errno()),
                        self.at_ino(&ino)
                            .map(|b| b.as_os_str())
                            .unwrap_or_else(|| OsStr::new("Unknown")),
                        fh
                    );
                    return Err(errno());
                }
                _ => return Ok(None),
            }
        }
        let dir_ent = unsafe { *dir_ent };
        let file_len = unsafe { CStr::from_ptr(dir_ent.d_name.as_ptr() as _) }
            .to_bytes()
            .len();
        let file_buf = unsafe { &*(&dir_ent.d_name[..file_len] as *const [i8] as *const [u8]) };
        let file = buf_to_osstr(file_buf);

        log::trace!("File {:?} under dir {:?}", file, ino);

        // This conversion is not always necessary on all systems.
        // The seek data has different names on different OSs
        #[allow(clippy::useless_conversion)]
        #[cfg(target_os = "macos")]
        let seek = dir_ent
            .d_seekoff
            .try_into()
            .expect("File length does not fit into i64");
        #[cfg(not(target_os = "macos"))]
        let seek = dir_ent.d_off;

        self.ino_paths.insert(
            dir_ent.d_ino,
            self.at_ino(&ino).expect("Valid ino number").join(file),
        );
        let mut buf = [0; MAX_FILENAME_LENGTH];
        &mut buf[..file_buf.len()].copy_from_slice(file_buf);
        Ok(Some((
            dir_ent.d_ino,
            seek,
            dir_ent.d_type.try_into().expect("Unknown file type"),
            buf,
        )))
    }

    fn releasedir(&mut self, fh: u64) -> Result<(), i32> {
        let res = unsafe { libc::closedir(fh as _) };
        if res == 0 {
            Ok(())
        } else {
            Err(errno())
        }
    }

    fn opendir(&mut self, ino: Ino, flags: i32) -> Result<(Fh, u32), i32> {
        let buf = if let Some(buf) = self.at_ino(&ino) {
            CString::new(buf.as_os_str().as_bytes()).expect("buf should not contain a null pointer")
        } else {
            log::error!("opendir: Invalid ino {:?}", ino);
            return Err(0);
        };
        let res = unsafe { libc::opendir(buf.as_ptr() as _) };
        if res.is_null() {
            log::error!("opendir: libc call failed with ERRNO=?");
            Err(errno())
        } else {
            Ok((res as u64, flags as u32))
        }
    }

    fn at_ino(&self, ino: &Ino) -> Option<&PathBuf> {
        if *ino == 1 || *ino == self.root_ino {
            Some(&self.root)
        } else {
            self.ino_paths.get(ino)
        }
    }

    fn _register_new_file(&mut self, file: OpenFile) -> Fh {
        let fh = file.fh();
        self.open_files.entry(fh).or_insert(file);
        fh
    }

    fn lookup(&mut self, parent: Ino, name: &[u8]) -> Result<(FileAttr, u64), i32> {
        let name = buf_to_osstr(name);
        let parent = if let Some(k) = self.at_ino(&parent) {
            k
        } else {
            log::error!(
                "Attempted lookup of parrent ino {:?}. File not found.",
                parent
            );
            return Err(libc::ENOENT);
        };
        let new_file = parent.join(name);
        let data = if let Ok(k) = fs::metadata(&new_file) {
            k
        } else {
            return Err(libc::ENOENT);
        };
        log::trace!(
            "Performed lookup on {:?} with parrent {:?}. Found new Ino {:?}",
            name,
            parent,
            new_file
        );
        self.ino_paths.insert(data.ino(), new_file);
        Ok(((&data).into(), 0))
    }

    fn getattr(&mut self, ino: Ino) -> Result<FileAttr, i32> {
        let handle;
        let buf = if ino == 1 {
            &self.root
        } else {
            handle = self.root.join(self.at_ino(&ino).unwrap());
            &handle
        };
        if let Ok(k) = fs::metadata(buf) {
            log::trace!("Replied with metadata of file {:?}", buf);
            Ok((&k).into())
        } else {
            log::error!("Failed lookup on ino {:?} = {:?}", ino, buf);
            Err(libc::ENOENT)
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
            initialized: false,
        })
    }
}

impl Drop for RDMAFs {
    fn drop(&mut self) {
        if self.initialized {
            self.connection[0] = Message::Exit;
            self.connection.send().unwrap();
        }
    }
}
impl Filesystem for RDMAFs {
    fn init(&mut self, _req: &Request<'_>, _config: &mut KernelConfig) -> Result<(), c_int> {
        // TODO: tune kernal with max read and write
        self.connection
            .recv()
            .map_err(|e| e.raw_os_error().unwrap_or(EREMOTEIO))?;
        assert!(
            self.connection[0] == Message::Startup { server: true },
            "Failed startup handshake (client)"
        );
        self.connection[0] = Message::Startup { server: false };
        self.connection
            .send()
            .map_err(|e| e.raw_os_error().unwrap_or(EREMOTEIO))?;
        self.initialized = true;
        Ok(())
    }

    fn destroy(&mut self, _req: &Request<'_>) {}

    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let name = name.as_bytes();
        assert!(name.len() < MAX_FILENAME_LENGTH);
        let mut buf = [0; MAX_FILENAME_LENGTH];
        &mut buf[..name.len()].copy_from_slice(name);
        self.connection[0] = Message::Lookup {
            parent,
            name: buf,
            attr: None,
            generation: 0,
            errno: None,
        };
        self.connection
            .send()
            .map_err(|e| e.raw_os_error().unwrap_or(EREMOTEIO))
            .unwrap();
        self.connection
            .recv()
            .map_err(|e| e.raw_os_error().unwrap_or(EREMOTEIO))
            .unwrap();
        match self.connection[0] {
            Message::Lookup {
                errno,
                attr,
                generation,
                ..
            } => {
                if let Some(errno) = errno {
                    reply.error(errno);
                } else {
                    reply.entry(
                        &std::time::Duration::ZERO,
                        &attr.expect("A reply should contain the attr"),
                        generation,
                    );
                }
            }
            Message::Null => reply.error(ENOSYS),
            _ => panic!("Expected lookup"),
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {
        self.connection[0] = Message::GetAttr {
            ino,
            attr: None,
            errno: None,
        };
        self.connection
            .send()
            .map_err(|e| e.raw_os_error().unwrap_or(EREMOTEIO))
            .unwrap();
        self.connection
            .recv()
            .map_err(|e| e.raw_os_error().unwrap_or(EREMOTEIO))
            .unwrap();
        match self.connection[0] {
            Message::GetAttr { attr, errno, .. } => {
                if let Some(errno) = errno {
                    reply.error(errno);
                } else {
                    reply.attr(
                        &std::time::Duration::ZERO,
                        &attr.expect("A reply should contain the attr"),
                    )
                }
            }
            Message::Null => reply.error(ENOSYS),
            _ => panic!("Expected getattr"),
        }
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
        _name: &OsStr,
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
        _name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        reply.error(ENOSYS);
    }

    fn unlink(&mut self, _req: &Request<'_>, _parent: u64, _name: &OsStr, reply: ReplyEmpty) {
        reply.error(ENOSYS);
    }

    fn rmdir(&mut self, _req: &Request<'_>, _parent: u64, _name: &OsStr, reply: ReplyEmpty) {
        reply.error(ENOSYS);
    }

    fn symlink(
        &mut self,
        _req: &Request<'_>,
        _parent: u64,
        _name: &OsStr,
        _link: &std::path::Path,
        reply: ReplyEntry,
    ) {
        reply.error(ENOSYS);
    }

    fn rename(
        &mut self,
        _req: &Request<'_>,
        _parent: u64,
        _name: &OsStr,
        _newparent: u64,
        _newname: &OsStr,
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
        _newname: &OsStr,
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

    fn opendir(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        self.connection[0] = Message::OpenDir {
            ino,
            flags,
            fh: 0,
            open_flags: 0,
            errno: None,
        };
        self.connection
            .send()
            .map_err(|e| e.raw_os_error().unwrap_or(EREMOTEIO))
            .unwrap();
        self.connection
            .recv()
            .map_err(|e| e.raw_os_error().unwrap_or(EREMOTEIO))
            .unwrap();
        match self.connection[0] {
            Message::OpenDir {
                fh,
                open_flags,
                errno,
                ..
            } => {
                if let Some(errno) = errno {
                    reply.error(errno);
                } else {
                    reply.opened(fh, open_flags);
                }
            }
            Message::Null => reply.error(ENOSYS),
            _ => panic!("Expected opendir"),
        }
    }

    // Protocal: Send a ReadDir request with correct ino, fh. We expect to
    // recieve a ReadDir back, and filled out. The process is statless, at the
    // communication level. We don't send any more requests when we are done
    // with the `fh`.
    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        _offset: i64,
        mut reply: ReplyDirectory,
    ) {
        self.connection[0] = Message::ReadDir {
            ino,
            fh,
            finished: false,
            errno: None,
            buf_ino: 0,
            offset: 0,
            kind: FileType::RegularFile,
            name: [0; MAX_FILENAME_LENGTH],
        };
        loop {
            self.connection
                .send()
                .map_err(|e| e.raw_os_error().unwrap_or(EREMOTEIO))
                .unwrap();
            self.connection
                .recv()
                .map_err(|e| e.raw_os_error().unwrap_or(EREMOTEIO))
                .unwrap();
            match &mut self.connection[0] {
                Message::Null => {
                    reply.error(ENOSYS);
                    return;
                }

                Message::ReadDir {
                    errno,
                    buf_ino,
                    offset,
                    kind,
                    name,
                    finished,
                    ..
                } => {
                    if *finished {
                        break;
                    } else if let Some(errno) = *errno {
                        reply.error(errno);
                        return;
                    } else if *buf_ino != 0
                        && reply.add(*buf_ino, *offset, *kind, buf_to_osstr(name))
                    {
                        break;
                    }
                }
                _ => panic!("Expected ReadDir"),
            }
        }
        reply.ok();
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
        fh: u64,
        _flags: i32,
        reply: ReplyEmpty,
    ) {
        self.connection[0] = Message::ReleaseDir { errno: None, fh };
        self.connection
            .send()
            .map_err(|e| e.raw_os_error().unwrap_or(EREMOTEIO))
            .unwrap();
        self.connection
            .recv()
            .map_err(|e| e.raw_os_error().unwrap_or(EREMOTEIO))
            .unwrap();
        match self.connection[0] {
            Message::Null => reply.error(ENOSYS),
            Message::ReleaseDir { errno, .. } => {
                if let Some(errno) = errno {
                    reply.error(errno);
                } else {
                    reply.ok();
                }
            }
            _ => panic!("Expected ReleaseDir"),
        }
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
        _name: &OsStr,
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
        _name: &OsStr,
        _size: u32,
        reply: ReplyXattr,
    ) {
        reply.error(ENOSYS);
    }

    fn listxattr(&mut self, _req: &Request<'_>, _ino: u64, _size: u32, reply: ReplyXattr) {
        reply.error(ENOSYS);
    }

    fn removexattr(&mut self, _req: &Request<'_>, _ino: u64, _name: &OsStr, reply: ReplyEmpty) {
        reply.error(ENOSYS);
    }

    fn access(&mut self, _req: &Request<'_>, _ino: u64, _mask: i32, reply: ReplyEmpty) {
        reply.ok(); // TODO: implement real access
    }

    fn create(
        &mut self,
        _req: &Request<'_>,
        _parent: u64,
        _name: &OsStr,
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

fn buf_to_osstr(b: &[u8]) -> &OsStr {
    OsStr::from_bytes(
        &b[..b
            .iter()
            .position(|e| *e == 0)
            .unwrap_or(MAX_FILENAME_LENGTH)
            .min(b.len())],
    )
}
