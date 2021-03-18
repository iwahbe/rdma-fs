#![feature(duration_zero)]

use clap::{App, Arg};
use env_logger;
use fuser::*;
use fuser::{spawn_mount, Filesystem, KernelConfig, Request};
use libc::{c_int, statfs, ENOSYS};
use std::collections::HashMap;
use std::convert::TryInto;
use std::ffi::{CStr, CString, OsStr};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use std::{fs, io::stdin};

use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};

use nix::errno::{errno, Errno};

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
    let _backround = spawn_mount(Mount::new(mount_reflect), &mountpoint, &[]).unwrap();
    let mut s = String::new();
    println!("Return on input");
    stdin().read_line(&mut s).expect("Failed to read input");
}

struct Mount {
    /// Where the root of `Mount` is located in the host file system.
    root: PathBuf,
    root_ino: Ino,
    ino_paths: HashMap<Ino, PathBuf>,
}

type Ino = u64;

impl Mount {
    fn new<T: Into<PathBuf>>(root: T) -> Self {
        Self {
            root: root.into(),
            ino_paths: HashMap::new(),
            root_ino: 0,
        }
    }

    fn at_ino(&self, ino: &Ino) -> Option<&PathBuf> {
        if *ino == 1 || *ino == self.root_ino {
            Some(&self.root)
        } else {
            self.ino_paths.get(ino)
        }
    }
}

impl Filesystem for Mount {
    fn init(&mut self, _req: &Request<'_>, _config: &mut KernelConfig) -> Result<(), c_int> {
        if !self.root.exists() || !self.root.is_dir() {
            return Err(1);
        }
        self.root = self.root.canonicalize().unwrap();
        let root_data = fs::metadata(&self.root).unwrap();
        self.root_ino = root_data.ino();
        log::info!("File system mounted to reflect {:?}", self.root);
        Ok(())
    }

    fn destroy(&mut self, _req: &Request<'_>) {
        log::info!("File system destroyed")
    }

    /// Open a file.
    /// Open flags (with the exception of O_CREAT, O_EXCL, O_NOCTTY and O_TRUNC) are
    /// available in flags. Filesystem may store an arbitrary file handle (pointer, index,
    /// etc) in fh, and use this in other all other file operations (read, write, flush,
    /// release, fsync). Filesystem may also implement stateless file I/O and not store
    /// anything in fh. There are also some flags (direct_io, keep_cache) which the
    /// filesystem may set, to change the way the file is opened. See fuse_file_info
    /// structure in <fuse_common.h> for more details.
    fn open(&mut self, _req: &Request<'_>, ino: Ino, flags: i32, reply: ReplyOpen) {
        if let Some(path) = self.at_ino(&ino) {
            log::trace!("Open called on ino {:?} = {:?}", ino, path);
            let path = CString::new(path.as_os_str().as_bytes()).unwrap();
            let res = unsafe { libc::open(path.as_ptr(), flags) };
            if res >= 0 {
                reply.opened(res as u64, flags as u32);
            } else {
                reply.error(errno());
            }
        } else {
            log::error!("Open failed with invalid ino {:?}", ino);
            reply.error(libc::EIO);
        }
    }

    /// Look up a directory entry by name and get its attributes.
    fn lookup(&mut self, _req: &Request<'_>, parent: Ino, name: &OsStr, reply: ReplyEntry) {
        let parent = if let Some(k) = self.at_ino(&parent) {
            k
        } else {
            reply.error(libc::ENOENT);
            log::error!(
                "Attempted lookup of parrent ino {:?}. File not found.",
                parent
            );
            return;
        };
        let new_file = parent.join(name);
        let data = if let Ok(k) = fs::metadata(&new_file) {
            k
        } else {
            reply.error(libc::ENOENT);
            return;
        };
        reply.entry(&std::time::Duration::ZERO, &(&data).into(), 0);
        log::trace!(
            "Performed lookup on {:?} with parrent {:?}. Found new Ino {:?}",
            name,
            parent,
            new_file
        );
        self.ino_paths.insert(data.ino(), new_file);
    }

    /// Get file attributes.
    fn getattr(&mut self, _req: &Request<'_>, ino: Ino, reply: ReplyAttr) {
        let handle;
        let buf = if ino == 1 {
            &self.root
        } else {
            handle = self.root.join(self.at_ino(&ino).unwrap());
            &handle
        };
        if let Ok(k) = fs::metadata(buf) {
            reply.attr(&std::time::Duration::ZERO, &(&k).into());
            log::trace!("Replied with metadata of file {:?}", buf);
        } else {
            log::error!("Failed lookup on ino {:?} = {:?}", ino, buf);
            reply.error(libc::ENOENT);
        };
    }

    /// Set file attributes.
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
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        log::error!("setattr failed: not yet implemented");
        reply.error(ENOSYS);
    }

    /// Read symbolic link.
    fn readlink(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyData) {
        log::error!("readlink failed: not yet implemented");
        reply.error(ENOSYS);
    }

    /// Create file node.
    /// Create a regular file, character device, block device, fifo or socket node.
    fn mknod(
        &mut self,
        _req: &Request<'_>,
        _parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        log::error!("mknod not yet implemented for {:?}", name);
        reply.error(ENOSYS);
    }

    /// Create a directory.
    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        _parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        log::error!("mkdir not yet implemented fro {:?}", name);
        reply.error(ENOSYS);
    }

    /// Remove a file.
    fn unlink(&mut self, _req: &Request<'_>, _parent: u64, name: &OsStr, reply: ReplyEmpty) {
        log::error!("Unlink failed on file {:?}", name);
        reply.error(ENOSYS);
    }

    /// Remove a directory.
    fn rmdir(&mut self, _req: &Request<'_>, _parent: u64, _name: &OsStr, reply: ReplyEmpty) {
        log::error!("rmdir failed: not yet implementd");
        reply.error(ENOSYS);
    }

    /// Create a symbolic link.
    fn symlink(
        &mut self,
        _req: &Request<'_>,
        _parent: u64,
        _name: &OsStr,
        _link: &Path,
        reply: ReplyEntry,
    ) {
        log::error!("symlink failed: not yet implemented");
        reply.error(ENOSYS);
    }

    /// Rename a file.
    fn rename(
        &mut self,
        _req: &Request<'_>,
        _parent: u64,
        _name: &OsStr,
        _newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        log::error!("Renaming file to {:?}, not yet implemented", newname);
        reply.error(ENOSYS);
    }

    /// Create a hard link.
    fn link(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _newparent: u64,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        log::error!(
            "Creating link to newname {:?}, not yet implemented",
            newname
        );
        reply.error(ENOSYS);
    }

    /// Read data.
    /// Read should send exactly the number of bytes requested except on EOF or error,
    /// otherwise the rest of the data will be substituted with zeroes. An exception to
    /// this is when the file has been opened in 'direct_io' mode, in which case the
    /// return value of the read system call will reflect the return value of this
    /// operation. fh will contain the value set by the open method, or will be undefined
    /// if the open method didn't set any value.
    ///
    /// flags: these are the file flags, such as O_SYNC. Only supported with ABI >= 7.9
    /// lock_owner: only supported with ABI >= 7.9
    fn read(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        log::trace!("Writing to fh {:?}", fh);
        let mut buf = vec![0; size as usize];
        let bytes_read = unsafe { libc::read(fh as _, buf.as_mut_ptr() as _, size as usize) };
        if bytes_read != -1 {
            reply.data(&buf);
        } else {
            reply.error(errno());
        }
    }

    /// Write data.
    /// Write should return exactly the number of bytes requested except on error. An
    /// exception to this is when the file has been opened in 'direct_io' mode, in
    /// which case the return value of the write system call will reflect the return
    /// value of this operation. fh will contain the value set by the open method, or
    /// will be undefined if the open method didn't set any value.
    ///
    /// write_flags: will contain FUSE_WRITE_CACHE, if this write is from the page cache. If set,
    /// the pid, uid, gid, and fh may not match the value that would have been sent if write cachin
    /// is disabled
    /// flags: these are the file flags, such as O_SYNC. Only supported with ABI >= 7.9
    /// lock_owner: only supported with ABI >= 7.9
    fn write(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        log::info!("Attempting to write to file at handle: {:?}", fh);
        let bytes_written = unsafe { libc::write(fh as _, data.as_ptr() as _, data.len()) };
        if bytes_written != -1 {
            log::trace!("wrote {:?} bytes to fh {:?}", bytes_written, fh);
            reply.written(bytes_written as _);
        } else {
            log::error!("Failed to write bytes to fh {:?}", fh);
            reply.error(errno());
        }
    }

    /// Flush method.
    /// This is called on each close() of the opened file. Since file descriptors can
    /// be duplicated (dup, dup2, fork), for one open call there may be many flush
    /// calls. Filesystems shouldn't assume that flush will always be called after some
    /// writes, or that if will be called at all. fh will contain the value set by the
    /// open method, or will be undefined if the open method didn't set any value.
    /// NOTE: the name of the method is misleading, since (unlike fsync) the filesystem
    /// is not forced to flush pending writes. One reason to flush data, is if the
    /// filesystem wants to return write errors. If the filesystem supports file locking
    /// operations (setlk, getlk) it should remove all locks belonging to 'lock_owner'.
    fn flush(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _lock_owner: u64,
        reply: ReplyEmpty,
    ) {
        let res = unsafe { libc::close(fh as _) };
        if res != 0 {
            log::error!(
                "flush: close syscall failed on fh {:?} with errorno: {:?}.",
                fh,
                res
            );
            reply.error(errno());
        } else {
            reply.ok();
        }
    }

    /// Release an open file.
    /// Release is called when there are no more references to an open file: all file
    /// descriptors are closed and all memory mappings are unmapped. For every open
    /// call there will be exactly one release call. The filesystem may reply with an
    /// error, but error values are not returned to close() or munmap() which triggered
    /// the release. fh will contain the value set by the open method, or will be undefined
    /// if the open method didn't set any value. flags will contain the same flags as for
    /// open.
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

    /// Synchronize file contents.
    /// If the datasync parameter is non-zero, then only the user data should be flushed,
    /// not the meta data.
    fn fsync(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        log::error!("fsync called but not yet implmeneted");
        reply.error(ENOSYS);
    }

    /// Open a directory.
    /// Filesystem may store an arbitrary file handle (pointer, index, etc) in fh, and
    /// use this in other all other directory stream operations (readdir, releasedir,
    /// fsyncdir). Filesystem may also implement stateless directory I/O and not store
    /// anything in fh, though that makes it impossible to implement standard conforming
    /// directory stream operations in case the contents of the directory can change
    /// between opendir and releasedir.
    fn opendir(&mut self, _req: &Request<'_>, ino: Ino, flags: i32, reply: ReplyOpen) {
        let buf = if let Some(buf) = self.at_ino(&ino) {
            CString::new(buf.as_os_str().as_bytes()).expect("buf should not contain a null pointer")
        } else {
            log::error!("opendir: Invalid ino {:?}", ino);
            return;
        };
        let res = unsafe { libc::opendir(buf.as_ptr() as _) };
        if res.is_null() {
            log::error!("opendir: libc call failed with ERRNO=?");
            reply.error(errno());
        } else {
            reply.opened(res as u64, flags as u32);
        }
    }

    /// Read directory.
    /// Send a buffer filled using buffer.fill(), with size not exceeding the
    /// requested size. Send an empty buffer on end of stream. fh will contain the
    /// value set by the opendir method, or will be undefined if the opendir method
    /// didn't set any value.
    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        _offset: i64,
        mut reply: ReplyDirectory,
    ) {
        loop {
            Errno::clear(); // Because it's not clear if readdir failed from it's output
            let dir_ent = unsafe { libc::readdir(fh as _) };
            if dir_ent.is_null() {
                use libc::*;
                match errno() {
                    EACCES | EBADF | EMFILE | ENFILE | ENOENT | ENOMEM | ENOTDIR => {
                        reply.error(errno());
                        log::error!(
                            "Encountered error {} reading directory {:?}, fh {:?}",
                            std::io::Error::from_raw_os_error(errno()),
                            self.at_ino(&ino)
                                .map(|b| b.as_os_str())
                                .unwrap_or(OsStr::new("Unknown")),
                            fh
                        );
                        return;
                    }
                    _ => break,
                }
            }
            let dir_ent = unsafe { *dir_ent };
            let file_len = unsafe { CStr::from_ptr(dir_ent.d_name.as_ptr() as _) }
                .to_bytes()
                .len();
            let file =
                OsStr::from_bytes(unsafe { std::mem::transmute(&dir_ent.d_name[..file_len]) });
            log::trace!("File {:?} under dir {:?}", file, ino);
            if dir_ent.d_ino == 0 {
                continue; // file has been deleted, but has not yet been removed
            }
            let full = reply.add(
                dir_ent.d_ino,
                dir_ent
                    .d_seekoff
                    .try_into()
                    .expect("File length does not fit into i64"),
                dir_ent.d_type.try_into().expect("Unknown file type"),
                file,
            );
            self.ino_paths.insert(
                dir_ent.d_ino,
                self.at_ino(&ino).expect("Valid ino number").join(file),
            );
            if full {
                break;
            }
        }
        reply.ok();
        log::trace!("Read directory at ino: {}", ino);
    }

    /// Read directory.
    /// Send a buffer filled using buffer.fill(), with size not exceeding the
    /// requested size. Send an empty buffer on end of stream. fh will contain the
    /// value set by the opendir method, or will be undefined if the opendir method
    /// didn't set any value.
    fn readdirplus(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        _offset: i64,
        reply: ReplyDirectoryPlus,
    ) {
        log::error!("Attempting to read directory plus at ino: {}", ino);
        reply.error(ENOSYS);
    }

    /// Release an open directory.
    /// For every opendir call there will be exactly one releasedir call. fh will
    /// contain the value set by the opendir method, or will be undefined if the
    /// opendir method didn't set any value.
    fn releasedir(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        reply: ReplyEmpty,
    ) {
        let res = unsafe { libc::closedir(fh as _) };
        if res == 0 {
            reply.ok();
        } else {
            reply.error(errno());
        }
    }

    /// Synchronize directory contents.
    /// If the datasync parameter is set, then only the directory contents should
    /// be flushed, not the meta data. fh will contain the value set by the opendir
    /// method, or will be undefined if the opendir method didn't set any value.
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

    /// Get file system statistics.
    fn statfs(&mut self, _req: &Request<'_>, ino: Ino, reply: ReplyStatfs) {
        let mut buf: statfs = unsafe { std::mem::MaybeUninit::uninit().assume_init() };
        let path = if let Some(k) = self.at_ino(&ino) {
            k.as_os_str()
        } else {
            log::error!("statfs: Attempted to access invalid ino {:?}", ino);
            reply.error(errno());
            return;
        };
        log::trace!("Replying with file system stats called on file {:?}", path);
        let cstr = CString::new(path.as_bytes()).unwrap();
        let e = unsafe { statfs(cstr.as_ptr(), &mut buf as _) };
        if e != 0 {
            log::error!(
                "Error {:?} attempting to get file system statistics on path {:?}, ino: {:?}",
                e,
                path,
                ino
            );
            reply.error(errno());
            return;
        }
        reply.statfs(
            buf.f_blocks,
            buf.f_bfree,
            buf.f_bavail,
            buf.f_files,
            buf.f_ffree,
            buf.f_bsize,
            255,
            buf.f_bsize, // Hardly ever used:
                         // https://stackoverflow.com/questions/54823541/what-do-f-bsize-and-f-frsize-in-struct-statvfs-stand-for
        );
    }

    /// Set an extended attribute.
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
        log::error!("setxattr failed: not yet implemented");
        reply.error(ENOSYS);
    }

    /// Get an extended attribute.
    /// If `size` is 0, the size of the value should be sent with `reply.size()`.
    /// If `size` is not 0, and the value fits, send it with `reply.data()`, or
    /// `reply.error(ERANGE)` if it doesn't.
    fn getxattr(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _name: &OsStr,
        _size: u32,
        reply: ReplyXattr,
    ) {
        log::error!("getxattr failed: not yet implemented");
        reply.error(ENOSYS);
    }

    /// List extended attribute names.
    /// If `size` is 0, the size of the value should be sent with `reply.size()`.
    /// If `size` is not 0, and the value fits, send it with `reply.data()`, or
    /// `reply.error(ERANGE)` if it doesn't.
    fn listxattr(&mut self, _req: &Request<'_>, _ino: u64, _size: u32, reply: ReplyXattr) {
        log::error!("listxattr failed: not yet implemented");
        reply.error(ENOSYS);
    }

    /// Remove an extended attribute.
    fn removexattr(&mut self, _req: &Request<'_>, _ino: u64, _name: &OsStr, reply: ReplyEmpty) {
        log::error!("removexattr failed: not yet implemented");
        reply.error(ENOSYS);
    }

    /// Check file access permissions.
    /// This will be called for the access() system call. If the 'default_permissions'
    /// mount option is given, this method is not called. This method is not called
    /// under Linux kernel versions 2.4.x
    fn access(&mut self, _req: &Request<'_>, ino: u64, mask: i32, reply: ReplyEmpty) {
        if let Some(k) = self.at_ino(&ino) {
            log::trace!("Attempted permissions access of file {:?}", k);
            match unsafe { libc::access(k.as_os_str().as_bytes().as_ptr() as _, mask) } {
                0 => reply.ok(),
                _ => reply.error(errno()),
            };
        } else {
            log::error!("Failed to get permissions: invalid ino: {:?}", ino);
            reply.error(ENOSYS);
        };
    }

    /// Create and open a file.
    /// If the file does not exist, first create it with the specified mode, and then
    /// open it. Open flags (with the exception of O_NOCTTY) are available in flags.
    /// Filesystem may store an arbitrary file handle (pointer, index, etc) in fh,
    /// and use this in other all other file operations (read, write, flush, release,
    /// fsync). There are also some flags (direct_io, keep_cache) which the
    /// filesystem may set, to change the way the file is opened. See fuse_file_info
    /// structure in <fuse_common.h> for more details. If this method is not
    /// implemented or under Linux kernel versions earlier than 2.6.15, the mknod()
    /// and open() methods will be called instead.
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
        log::info!("create called on file");
        if let Some(parent) = self.at_ino(&parent) {
            let path = parent.join(name);
            let c_str = CString::new(path.as_os_str().as_bytes())
                .expect("Path does not have a null terminator");
            let fd = unsafe { libc::open(c_str.as_ptr(), flags | libc::O_CREAT | libc::O_TRUNC) };
            if fd >= 0 {
                let attr = fs::metadata(&path).unwrap();
                self.ino_paths.insert(attr.ino(), path);
                reply.created(
                    &std::time::Duration::ZERO,
                    &(&attr).into(),
                    0,
                    fd as _,
                    flags as _,
                );
            } else {
                log::error!("Failed to create file {:?} with errno {:?}", name, errno());
                reply.error(errno());
            }
        }
    }

    /// Test for a POSIX file lock.
    fn getlk(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        _lock_owner: u64,
        _start: u64,
        _end: u64,
        _typ: i32,
        _pid: u32,
        reply: ReplyLock,
    ) {
        log::error!("getlk on ino: {:?}", ino);
        reply.error(ENOSYS);
    }

    /// Acquire, modify or release a POSIX file lock.
    /// For POSIX threads (NPTL) there's a 1-1 relation between pid and owner, but
    /// otherwise this is not always the case.  For checking lock ownership,
    /// 'fi->owner' must be used. The l_pid field in 'struct flock' should only be
    /// used to fill in this field in getlk(). Note: if the locking methods are not
    /// implemented, the kernel will still allow file locking to work locally.
    /// Hence these are only interesting for network filesystems and similar.
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
        log::error!("setlk failed: not yet implemented");
        reply.error(ENOSYS);
    }

    /// Map block index within file to block index within device.
    /// Note: This makes sense only for block device backed filesystems mounted
    /// with the 'blkdev' option
    fn bmap(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _blocksize: u32,
        _idx: u64,
        reply: ReplyBmap,
    ) {
        log::error!("bmap failed: not yet implemented");
        reply.error(ENOSYS);
    }

    /// control device
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
        log::error!("ioctl failed: not yet implemented");
        reply.error(ENOSYS);
    }

    /// Preallocate or deallocate space to a file
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
        log::error!("falocate failed: not yet implemented");
        reply.error(ENOSYS);
    }

    /// Reposition read/write file offset
    fn lseek(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        whence: i32,
        reply: ReplyLseek,
    ) {
        let offset = unsafe { libc::lseek(fh as _, offset, whence) };
        if offset == -1 {
            log::error!("lseek failed with error");
            reply.error(errno());
        } else {
            reply.offset(offset);
        }
    }

    /// Copy the specified range from the source inode to the destination inode
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
        log::error!("copy_file_range failed: not yet implemented");
        reply.error(ENOSYS);
    }

    /// macOS only: Rename the volume. Set fuse_init_out.flags during init to
    /// FUSE_VOL_RENAME to enable
    #[cfg(target_os = "macos")]
    fn setvolname(&mut self, _req: &Request<'_>, _name: &OsStr, reply: ReplyEmpty) {
        log::error!("setvolname failed: not yet implemented");
        reply.error(ENOSYS);
    }

    /// macOS only (undocumented)
    #[cfg(target_os = "macos")]
    fn exchange(
        &mut self,
        _req: &Request<'_>,
        _parent: u64,
        _name: &OsStr,
        _newparent: u64,
        _newname: &OsStr,
        _options: u64,
        reply: ReplyEmpty,
    ) {
        log::error!("exchange failed: not yet implemented");
        reply.error(ENOSYS);
    }

    /// macOS only: Query extended times (bkuptime and crtime). Set fuse_init_out.flags
    /// during init to FUSE_XTIMES to enable
    #[cfg(target_os = "macos")]
    fn getxtimes(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyXTimes) {
        log::error!("getxtimes failed: not yet implemented");
        reply.error(ENOSYS);
    }
}
