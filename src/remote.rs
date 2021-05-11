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
const READ_WRITE_BUFFER_SIZE: usize = 2usize.pow(13);

macro_rules! exchange {
    ($msg: expr, $con: expr) => {
        $con[0] = $msg;
        exchange!($con);
    };
    ($con: expr) => {
        $con.send()
            .map_err(|e| e.raw_os_error().unwrap_or(EREMOTEIO))
            .unwrap();
        $con.recv()
            .map_err(|e| e.raw_os_error().unwrap_or(EREMOTEIO))
            .unwrap();
    };
}

/// The commands that an `RDMAFs` can issue to the server. Each command contains
/// the information necessary for both a request and a reply. The client loads
/// the request fields, and gets back a fully filled out reply.
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

    /// Open a file.
    Open {
        errno: Option<i32>,
        ino: Ino,
        flags: i32,
        fh: Fh,
        open_flags: u32,
    },

    /// Release a file, called once for each fh
    Release {
        errno: Option<i32>,
        ino: Ino,
        fh: Fh,
    },

    /// Read data from
    Read {
        errno: Option<i32>,
        fh: Fh,
        offset: i64,
        size: u32,
        buf: [u8; READ_WRITE_BUFFER_SIZE],
    },

    Write {
        errno: Option<i32>,
        fh: Fh,
        offset: i64,
        data: [u8; READ_WRITE_BUFFER_SIZE],
        /// When a request is made, `written` holds the number of bytes to
        /// write. A reply contains the number of bytes written.
        written: u32,
    },

    Flush {
        errno: Option<i32>,
        fh: Fh,
    },

    LSeek {
        errno: Option<i32>,
        fh: Fh,
        offset: i64,
        whence: i32,
    },

    Create {
        errno: Option<i32>,
        parent: Ino,
        name: [u8; MAX_FILENAME_LENGTH],
        flags: i32,
        //Reply
        attr: Option<FileAttr>,
        generation: u64,
        fh: Fh,
        open_flags: u32,
    },

    Mkdir {
        errno: Option<i32>,
        parent: Ino,
        name: [u8; MAX_FILENAME_LENGTH],
        mode: u32,
        umask: u32,
        //Reply
        attr: Option<FileAttr>,
        generation: u64,
    },

    Unlink {
        errno: Option<i32>,
        parent: Ino,
        name: [u8; MAX_FILENAME_LENGTH],
    },

    Rmdir {
        errno: Option<i32>,
        parent: Ino,
        name: [u8; MAX_FILENAME_LENGTH],
    },

    Rename {
        errno: Option<i32>,
        parent: Ino,
        name: [u8; MAX_FILENAME_LENGTH],
        newparent: Ino,
        newname: [u8; MAX_FILENAME_LENGTH],
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

            Message::Open {
                errno,
                ino,
                flags,
                fh,
                open_flags,
            } => match data.open(*ino, *flags) {
                Ok((file_handle, flags)) => {
                    *errno = None;
                    *fh = file_handle;
                    *open_flags = flags;
                }
                Err(e) => *errno = Some(e),
            },

            Message::Release { errno, ino, fh } => *errno = data.release(*ino, *fh).err(),

            Message::Read {
                errno,
                fh,
                offset,
                size,
                buf,
            } => match data.read(*fh, *offset, *size, buf) {
                Ok(bytes_read) => *size = bytes_read as _,
                Err(e) => *errno = Some(e),
            },

            Message::Write {
                errno,
                fh,
                offset,
                data: buf,
                written,
            } => match data.write(*fh, *offset, &buf[..*written as _]) {
                Ok(k) => {
                    *errno = None;
                    *written = k;
                }
                Err(e) => *errno = Some(e),
            },

            Message::Flush { errno, fh } => *errno = data.flush(*fh).err(),

            Message::LSeek {
                errno,
                fh,
                offset,
                whence,
            } => match data.lseek(*fh, *offset, *whence) {
                Ok(k) => *offset = k,
                Err(e) => *errno = Some(e),
            },

            Message::Create {
                errno,
                parent,
                name,
                flags,
                attr,
                generation,
                fh,
                open_flags,
            } => match data.create(*parent, buf_to_osstr(name), *flags) {
                Ok((f_attr, gen, new_fh, flags)) => {
                    *attr = Some(f_attr);
                    *generation = gen;
                    *fh = new_fh;
                    *open_flags = flags;
                }
                Err(e) => *errno = Some(e),
            },

            Message::Mkdir {
                errno,
                parent,
                name,
                mode,
                umask,
                attr,
                generation,
            } => match data.mkdir(*parent, buf_to_osstr(name), *mode, *umask) {
                Ok((f_attr, f_gen)) => {
                    *attr = Some(f_attr);
                    *generation = f_gen;
                }
                Err(e) => *errno = Some(e),
            },

            Message::Unlink {
                errno,
                parent,
                name,
            } => *errno = data.unlink(*parent, buf_to_osstr(name)).err(),

            Message::Rmdir {
                errno,
                parent,
                name,
            } => *errno = data.rmdir(*parent, buf_to_osstr(name)).err(),

            Message::Rename {
                errno,
                parent,
                name,
                newparent,
                newname,
            } => {
                *errno = data
                    .rename(
                        *parent,
                        buf_to_osstr(name),
                        *newparent,
                        buf_to_osstr(newname),
                    )
                    .err()
            }
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

/// These are the local side operations that correspond to `local.rs`.
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

    /// Rename a file.
    fn rename(
        &mut self,
        parent: Ino,
        name: &OsStr,
        newparent: Ino,
        newname: &OsStr,
    ) -> Result<(), i32> {
        // TODO: revalidate the [ino <-> path] map
        let old_name = CString::new(name.as_bytes()).unwrap();
        let newname = CString::new(newname.as_bytes()).unwrap();
        let res = unsafe {
            libc::renameat(
                parent as _,
                old_name.as_ptr(),
                newparent as _,
                newname.as_ptr(),
            )
        };
        match res {
            0 => Ok(()),
            _ => Err(errno()),
        }
    }

    /// Remove a directory.
    fn rmdir(&mut self, parent: Ino, name: &OsStr) -> Result<(), i32> {
        let path = self.at_ino(&parent).ok_or(libc::ENOENT)?.join(name);
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let res = unsafe { libc::rmdir(path.as_ptr()) };
        match res {
            0 => Ok(()),
            _ => Err(errno()),
        }
    }

    /// Remove a file.
    fn unlink(&mut self, parent: u64, name: &OsStr) -> Result<(), i32> {
        if let Some(parent) = self.at_ino(&parent) {
            let fname = CString::new(parent.join(name).as_os_str().as_bytes()).unwrap();
            let res = unsafe { libc::unlink(fname.as_ptr()) };
            if res == 0 {
                Ok(())
            } else {
                Err(errno())
            }
        } else {
            log::error!("Unlink failed on invalid parent ino {:?}", parent);
            Err(libc::ENOENT)
        }
    }

    /// Create a directory.
    fn mkdir(
        &mut self,
        parent: Ino,
        name: &OsStr,
        mode: u32,
        umask: u32,
    ) -> Result<(FileAttr, u64), i32> {
        let res: Result<FileAttr, i32> = try {
            let name = self.at_ino(&parent).ok_or(libc::ENOENT)?.join(name);
            let c_name = CString::new(name.as_os_str().as_bytes()).unwrap();
            // NOTE: unsure about the bit-and
            let res = unsafe { libc::mkdir(c_name.as_ptr(), (mode & umask) as _) };
            match res {
                0 => fs::metadata(&name).as_ref().unwrap().try_into().unwrap(),
                _ => Err(errno())?,
            }
        };
        res.map(|k| (k, 0))
    }

    fn create(
        &mut self,
        parent: Ino,
        name: &OsStr,
        flags: i32,
    ) -> Result<(FileAttr, u64, Fh, u32), i32> {
        if let Some(parent) = self.at_ino(&parent) {
            let path = parent.join(name);
            log::info!("create called on file {:?}", path);
            let file = match FileBuilder::from_flags(flags)
                .create(true)
                .read(true)
                .write(true)
                .path(&path)
            {
                Ok(k) => k,
                Err(e) => {
                    log::error!("Failed to create file {:?} with error: {}", path, e);
                    return Err(e.raw_os_error().unwrap());
                }
            };
            let meta = file.metadata().expect("already called, so should work");
            self.ino_paths.insert(meta.ino(), path);
            let fd = self.register_new_file(file);
            Ok(((&meta).into(), 0, fd as _, flags as _))
        } else {
            log::error!("Failed to create file {:?} with errno {:?}", name, errno());
            Err(errno())
        }
    }

    /// Reposition read/write file offset
    fn lseek(&mut self, fh: u64, offset: i64, whence: i32) -> Result<i64, i32> {
        let offset = unsafe { libc::lseek(fh as _, offset, whence) };
        if offset == -1 {
            log::error!("lseek failed with error");
            Err(errno())
        } else {
            Ok(offset)
        }
    }

    fn flush(&mut self, fh: Fh) -> Result<(), i32> {
        if let Some(f) = self.open_files.get_mut(&fh) {
            if let Some(r) = f.flush().err() {
                Err(r.raw_os_error().unwrap())
            } else {
                Ok(())
            }
        } else {
            Err(libc::ENOENT)
        }
    }

    fn write(&mut self, fh: Fh, offset: i64, data: &[u8]) -> Result<u32, i32> {
        log::info!("Attempting to write to file at handle: {:?}", fh);
        if let Some(f) = self.open_files.get_mut(&fh) {
            match f.write(data, offset) {
                Ok(len) => Ok(len as _),
                Err(e) => {
                    log::error!("Failed to wtite bytes: {}", e);
                    Err(e.raw_os_error().unwrap())
                }
            }
        } else {
            log::error!(
                "Failed to write bytes to fh {:?}, could not find open file. There are {} open files.",
                fh, self.open_files.keys().len()
            );
            Err(0)
        }
    }

    fn read(
        &mut self,
        fh: u64,
        offset: i64,
        size: u32,
        buf: &mut [u8; READ_WRITE_BUFFER_SIZE],
    ) -> Result<usize, i32> {
        let size = size as usize;
        assert!(size <= buf.len());
        if let Some(f) = self.open_files.get_mut(&(fh as _)) {
            match f.read(&mut *buf, offset, size) {
                Ok(bytes_read) => {
                    log::info!(
                        "Read {} ({} requested) bytes into file {}",
                        bytes_read,
                        size,
                        fh
                    );
                    Ok(bytes_read)
                }
                Err(e) => Err(e.raw_os_error().unwrap_or(1) as _),
            }
        } else {
            Err(libc::EBADF)
        }
    }

    fn release(&mut self, ino: u64, fh: u64) -> Result<(), i32> {
        log::trace!("Released file {:?} with fh {:?}", self.at_ino(&ino), fh);
        self.open_files.remove(&fh);
        Ok(())
    }

    fn open(&mut self, ino: Ino, flags: i32) -> Result<(Fh, u32), i32> {
        if let Some(path) = self.at_ino(&ino) {
            match FileBuilder::from_flags(flags)
                .read(true)
                .write(true)
                .path(path)
            {
                Ok(file) => {
                    let fh = self.register_new_file(file);
                    Ok((fh as _, flags as _))
                }
                Err(e) => Err(e.raw_os_error().unwrap_or(libc::EIO)),
            }
        } else {
            log::error!("Open failed with invalid ino {:?}", ino);
            Err(libc::EIO)
        }
    }

    fn readdir(
        &mut self,
        ino: Ino,
        fh: Fh,
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
        // We need to allow an extra step to convert u8 to i8 on some machines
        let file_buf = unsafe { &*(&dir_ent.d_name[..file_len] as *const [_] as *const [u8]) };
        let file = buf_to_osstr(file_buf);

        log::trace!("File {:?} under dir {:?}", file, ino);

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

    fn register_new_file(&mut self, file: OpenFile) -> Fh {
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
    fn init(&mut self, _req: &Request<'_>, config: &mut KernelConfig) -> Result<(), c_int> {
        config.set_max_write(READ_WRITE_BUFFER_SIZE as _).unwrap();
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
        exchange!(
            Message::Lookup {
                parent,
                name: buf,
                attr: None,
                generation: 0,
                errno: None,
            },
            self.connection
        );
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
        exchange!(
            Message::GetAttr {
                ino,
                attr: None,
                errno: None,
            },
            self.connection
        );
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

    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        let mut buf = [0; MAX_FILENAME_LENGTH];
        buf[0..name.len()].copy_from_slice(name.as_bytes());

        exchange!(
            Message::Mkdir {
                errno: None,
                parent,
                name: buf,
                mode,
                umask,
                attr: None,
                generation: 0,
            },
            self.connection
        );

        match self.connection[0] {
            Message::Mkdir {
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
                        &attr.expect("File attr info filled"),
                        generation,
                    );
                }
            }
            Message::Null => reply.error(ENOSYS),
            _ => panic!("Expected open"),
        }
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let mut buf = [0; MAX_FILENAME_LENGTH];
        buf[0..name.len()].copy_from_slice(name.as_bytes());

        exchange! {
            Message::Unlink {
                errno: None,
                parent,
                name: buf,
            },
            self.connection
        };

        match self.connection[0] {
            Message::Unlink { errno, .. } => {
                if let Some(errno) = errno {
                    reply.error(errno);
                } else {
                    reply.ok();
                }
            }
            Message::Null => reply.error(ENOSYS),
            _ => panic!("Expected Unlink"),
        }
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let mut buf = [0; MAX_FILENAME_LENGTH];
        buf[0..name.len()].copy_from_slice(name.as_bytes());
        exchange! {
            Message::Rmdir {errno: None, parent, name: buf},
            self.connection
        };
        match self.connection[0] {
            Message::Rmdir { errno, .. } => {
                if let Some(errno) = errno {
                    reply.error(errno);
                } else {
                    reply.ok();
                }
            }
            Message::Null => reply.error(ENOSYS),
            _ => panic!("Expected Rmdir"),
        }
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
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let mut buf = [0; MAX_FILENAME_LENGTH];
        buf[0..name.len()].copy_from_slice(name.as_bytes());
        let mut newbuf = [0; MAX_FILENAME_LENGTH];
        newbuf[0..newname.len()].copy_from_slice(newname.as_bytes());

        exchange! {
            Message::Rename {
                errno: None,
                parent,
                name: buf,
                newparent,
                newname: newbuf,
            }, self.connection
        };
        match self.connection[0] {
            Message::Rename { errno, .. } => {
                if let Some(errno) = errno {
                    reply.error(errno);
                } else {
                    reply.ok();
                }
            }
            Message::Null => reply.error(ENOSYS),
            _ => panic!("Expected Rename"),
        }
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

    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        exchange!(
            Message::Open {
                ino,
                flags,
                fh: 0,
                open_flags: 0,
                errno: None,
            },
            self.connection
        );
        match self.connection[0] {
            Message::Open {
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
            _ => panic!("Expected open"),
        }
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        exchange!(
            Message::Read {
                errno: None,
                fh,
                offset,
                size,
                buf: [0; READ_WRITE_BUFFER_SIZE],
            },
            self.connection
        );
        match self.connection[0] {
            Message::Read {
                errno, buf, size, ..
            } => {
                if let Some(errno) = errno {
                    reply.error(errno);
                } else {
                    reply.data(&buf[..size as usize]);
                }
            }
            Message::Null => reply.error(ENOSYS),
            _ => panic!("Expected Read"),
        }
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        assert!(data.len() <= READ_WRITE_BUFFER_SIZE);
        let mut buf = [0; READ_WRITE_BUFFER_SIZE];
        buf[0..data.len()].copy_from_slice(data);
        exchange!(
            Message::Write {
                errno: None,
                fh,
                offset,
                data: buf,
                written: data.len() as _,
            },
            self.connection
        );
        match self.connection[0] {
            Message::Write { errno, written, .. } => {
                if let Some(errno) = errno {
                    reply.error(errno);
                } else {
                    reply.written(written);
                }
            }
            Message::Null => reply.error(ENOSYS),
            _ => panic!("Expected Write"),
        }
    }

    fn flush(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _lock_owner: u64,
        reply: ReplyEmpty,
    ) {
        exchange!(Message::Flush { errno: None, fh }, self.connection);
        match self.connection[0] {
            Message::Flush { errno, .. } => {
                if let Some(errno) = errno {
                    reply.error(errno);
                } else {
                    reply.ok();
                }
            }
            Message::Null => reply.error(ENOSYS),
            _ => panic!("Expected Flush"),
        }
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        exchange!(
            Message::Release {
                ino,
                fh,
                errno: None,
            },
            self.connection
        );
        match self.connection[0] {
            Message::Release { errno, .. } => {
                if let Some(errno) = errno {
                    reply.error(errno);
                } else {
                    reply.ok();
                }
            }
            Message::Null => reply.error(ENOSYS),
            _ => panic!("Expected Release"),
        }
    }

    fn opendir(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        exchange!(
            Message::OpenDir {
                ino,
                flags,
                fh: 0,
                open_flags: 0,
                errno: None,
            },
            self.connection
        );
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
            exchange!(self.connection);
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

    fn releasedir(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        reply: ReplyEmpty,
    ) {
        exchange!(Message::ReleaseDir { errno: None, fh }, self.connection);
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

    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyStatfs) {
        reply.statfs(0, 0, 0, 0, 0, 512, 255, 0);
    }

    fn access(&mut self, _req: &Request<'_>, _ino: u64, _mask: i32, reply: ReplyEmpty) {
        reply.ok(); // TODO: implement real access
    }

    fn create(
        &mut self,
        _req: &Request<'_>,
        parent: Ino,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let mut buf = [0; MAX_FILENAME_LENGTH];
        buf[0..name.len()].copy_from_slice(name.as_bytes());
        exchange!(
            Message::Create {
                errno: None,
                parent,
                name: buf,
                flags,
                attr: None,
                generation: 0,
                fh: 0,
                open_flags: 0,
            },
            self.connection
        );
        match self.connection[0] {
            Message::Null => reply.error(ENOSYS),
            Message::Create {
                errno,
                attr,
                generation,
                fh,
                open_flags,
                ..
            } => {
                if let Some(errno) = errno {
                    reply.error(errno);
                } else {
                    reply.created(
                        &std::time::Duration::ZERO,
                        &attr.expect("A filled attribute for create"),
                        generation,
                        fh,
                        open_flags,
                    );
                }
            }
            _ => panic!("Expected Create"),
        }
    }

    fn lseek(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        whence: i32,
        reply: ReplyLseek,
    ) {
        exchange!(
            Message::LSeek {
                errno: None,
                fh,
                offset,
                whence,
            },
            self.connection
        );
        match self.connection[0] {
            Message::Null => reply.error(ENOSYS),
            Message::LSeek { errno, offset, .. } => {
                if let Some(errno) = errno {
                    reply.error(errno);
                } else {
                    reply.offset(offset);
                }
            }
            _ => panic!("Expected LSeek"),
        }
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
