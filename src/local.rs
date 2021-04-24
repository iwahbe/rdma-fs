use crate::file::{FileBuilder, OpenFile};
use fuser::*;
use fuser::{Filesystem, KernelConfig, Request};
use libc::{c_int, statfs, ENOSYS};
use nix::errno::{errno, Errno};
use std::collections::HashMap;
use std::convert::TryInto;
use std::ffi::{CStr, CString, OsStr};
use std::fs;
use std::time::SystemTime;
use std::{
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
};

use crate::{Fh, Ino};

/// A filesystem that reflects a local file system.
pub struct LocalMount {
    /// Where the root of `Mount` is located in the host file system.
    root: PathBuf,
    /// The ino of the root of the reflected file system.
    root_ino: Ino,
    ino_paths: HashMap<Ino, PathBuf>,
    open_files: HashMap<Fh, OpenFile>,
}

impl LocalMount {
    pub fn new<T: Into<PathBuf>>(root: T) -> Self {
        LocalMount {
            root: root.into(),
            ino_paths: HashMap::new(),
            root_ino: 0,
            open_files: HashMap::new(),
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
}

impl Filesystem for LocalMount {
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
        self.open_files.clear();
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
            match FileBuilder::from_flags(flags)
                .read(true)
                .write(true)
                .path(path)
            {
                Ok(file) => {
                    let fh = self.register_new_file(file);
                    reply.opened(fh as _, flags as _);
                }
                Err(e) => reply.error(e.raw_os_error().unwrap_or(libc::EIO)),
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
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        ctime: Option<SystemTime>,
        fh: Option<u64>,
        crtime: Option<SystemTime>,
        chgtime: Option<SystemTime>,
        bkuptime: Option<SystemTime>,
        flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let res = try {
            let path = self.at_ino(&ino).ok_or(libc::ENOENT)?;
            let mut attr: FileAttr = fs::metadata(path).as_ref().unwrap().try_into().unwrap();
            macro_rules! maybe_set_attr {
                ($name: tt) => {
                    if let Some($name) = $name {
                        attr.$name = $name
                    }
                };
                ($name: tt, "time") => {
                    if let Some($name) = $name {
                        attr.$name = match $name {
                            TimeOrNow::Now => SystemTime::now(),
                            TimeOrNow::SpecificTime(t) => t,
                        }
                    }
                };
                ($name: tt, "ignore") => {
                    let _ = $name;
                };
            }
            maybe_set_attr!(mode, "ignore");
            maybe_set_attr!(uid);
            maybe_set_attr!(gid);
            maybe_set_attr!(size);
            maybe_set_attr!(atime, "time");
            maybe_set_attr!(mtime, "time");
            maybe_set_attr!(ctime);
            maybe_set_attr!(fh, "ignore");
            maybe_set_attr!(crtime);
            maybe_set_attr!(chgtime, "ignore");
            maybe_set_attr!(bkuptime, "ignore");
            maybe_set_attr!(flags);
            attr
        };
        match res {
            Ok(k) => reply.attr(&std::time::Duration::ZERO, &k),
            Err(e) => reply.error(e),
        }
    }

    /// Read symbolic link.
    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        let res = try {
            let path = self.at_ino(&ino).ok_or(libc::ENOENT)?;
            let path = CString::new(path.as_os_str().as_bytes()).unwrap();
            static BUF: &[u8] = &[0; libc::PATH_MAX as usize];
            let res = unsafe { libc::readlink(path.as_ptr(), BUF.as_ptr() as _, BUF.len()) };
            match res {
                size @ _ if size >= 0 => &BUF[..size as usize],
                _ => Err(errno())?,
            }
        };
        match res {
            Ok(k) => reply.data(k),
            Err(e) => reply.error(e),
        }
    }

    /// Create a directory.
    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        parent: Ino,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        let res = try {
            let name = self.at_ino(&parent).ok_or(libc::ENOENT)?.join(name);
            let c_name = CString::new(name.as_os_str().as_bytes()).unwrap();
            // NOTE: unsure about the bit-and
            let res = unsafe { libc::mkdir(c_name.as_ptr(), (mode & umask) as _) };
            match res {
                0 => fs::metadata(&name).as_ref().unwrap().try_into().unwrap(),
                _ => Err(errno())?,
            }
        };
        match res {
            Ok(k) => reply.entry(&std::time::Duration::ZERO, &k, 0),
            Err(e) => reply.error(e),
        }
    }

    /// Remove a file.
    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        if let Some(parent) = self.at_ino(&parent) {
            let fname = CString::new(parent.join(name).as_os_str().as_bytes()).unwrap();
            let res = unsafe { libc::unlink(fname.as_ptr()) };
            if res == 0 {
                reply.ok()
            } else {
                reply.error(errno())
            }
        } else {
            log::error!("Unlink failed on invalid parent ino {:?}", parent);
            reply.error(libc::ENOENT);
        }
    }

    /// Remove a directory.
    fn rmdir(&mut self, _req: &Request<'_>, parent: Ino, name: &OsStr, reply: ReplyEmpty) {
        let res = try {
            let path = self.at_ino(&parent).ok_or(libc::ENOENT)?.join(name);
            let path = CString::new(path.as_os_str().as_bytes()).unwrap();
            let res = unsafe { libc::rmdir(path.as_ptr()) };
            match res {
                0 => (),
                _ => Err(errno())?,
            }
        };
        match res {
            Ok(_) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    /// Create a symbolic link.
    fn symlink(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        link: &Path,
        reply: ReplyEntry,
    ) {
        let res = try {
            let path = self.at_ino(&parent).ok_or(libc::ENOENT)?.join(name);
            let path = CString::new(path.as_os_str().as_bytes()).unwrap();
            let c_link = CString::new(link.as_os_str().as_bytes()).unwrap();
            let res = unsafe { libc::symlink(path.as_ptr(), c_link.as_ptr()) };
            match res {
                0 => fs::metadata(link).as_ref().unwrap().into(),
                _ => Err(errno())?,
            }
        };
        match res {
            Ok(k) => reply.entry(&std::time::Duration::ZERO, &k, 0),
            Err(e) => reply.error(e),
        }
    }

    /// Rename a file.
    fn rename(
        &mut self,
        _req: &Request<'_>,
        parent: Ino,
        name: &OsStr,
        newparent: Ino,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        // TODO: revalidate the [ino <-> path] map
        let res = try {
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
                0 => (),
                _ => Err(errno())?,
            }
        };
        match res {
            Ok(_) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    /// Create a hard link.
    fn link(
        &mut self,
        _req: &Request<'_>,
        ino: Ino,
        newparent: Ino,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        let res = try {
            let old_name = CString::new(
                self.at_ino(&ino)
                    .ok_or(libc::ENOENT)?
                    .as_os_str()
                    .as_bytes(),
            )
            .unwrap();
            let newparent = self.at_ino(&newparent).ok_or(libc::ENOENT)?;
            let path = newparent.join(newname);
            let path = path.as_os_str();
            let newname = CString::new(path.as_bytes()).unwrap();
            let res = unsafe { libc::link(old_name.as_ptr(), newname.as_ptr()) };
            match res {
                0 => fs::metadata(path).as_ref().unwrap().try_into().unwrap(),
                _ => Err(errno())?,
            }
        };
        match res {
            Ok(k) => reply.entry(&std::time::Duration::ZERO, &k, 0),
            Err(e) => reply.error(e),
        }
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
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let size = size as usize;
        if let Some(f) = self.open_files.get_mut(&(fh as _)) {
            let mut buf = vec![0; size];
            match f.read(&mut buf, offset) {
                Ok(bytes_read) => {
                    log::info!("Read {} bytes into file {}", bytes_read, fh);
                    reply.data(&buf);
                }
                Err(e) => reply.error(e.raw_os_error().unwrap_or(1) as _),
            }
        } else {
            reply.error(libc::EBADF)
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
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        log::info!("Attempting to write to file at handle: {:?}", fh);
        if let Some(f) = self.open_files.get_mut(&fh) {
            match f.write(data, offset) {
                Ok(len) => reply.written(len as _),
                Err(e) => {
                    log::error!("Failed to wtite bytes: {}", e);
                    reply.error(e.raw_os_error().unwrap());
                }
            }
        } else {
            log::error!(
                "Failed to write bytes to fh {:?}, could not find open file. There are {} open files.",
                fh, self.open_files.keys().len()
            );
            reply.error(0);
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
        if let Some(f) = self.open_files.get_mut(&fh) {
            if let Some(r) = f.flush().err() {
                reply.error(r.raw_os_error().unwrap());
            } else {
                reply.ok();
            }
        } else {
            reply.error(libc::ENOENT);
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
        ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        log::trace!("Released file {:?} with fh {:?}", self.at_ino(&ino), fh);
        self.open_files.remove(&fh);
        reply.ok();
    }

    /// Synchronize file contents.
    /// If the datasync parameter is non-zero, then only the user data should be flushed,
    /// not the meta data.
    fn fsync(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        if let Some(f) = self.open_files.get_mut(&fh) {
            match f.flush() {
                Ok(_) => reply.ok(),
                Err(e) => reply.error(e.raw_os_error().unwrap()),
            }
        }
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
                                .unwrap_or_else(|| OsStr::new("Unknown")),
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
            let file = OsStr::from_bytes(unsafe {
                &*(&dir_ent.d_name[..file_len] as *const [i8] as *const [u8])
            });
            log::trace!("File {:?} under dir {:?}", file, ino);

            if dir_ent.d_ino == 0 {
                continue; // file has been deleted, but has not yet been removed
            }

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

            let full = reply.add(
                dir_ent.d_ino,
                seek,
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
            buf.f_blocks as _,
            buf.f_bfree as _,
            buf.f_bavail as _,
            buf.f_files as _,
            buf.f_ffree as _,
            buf.f_bsize as _,
            255,
            buf.f_bsize as _, // Hardly ever used:
                              // https://stackoverflow.com/questions/54823541/what-do-f-bsize-and-f-frsize-in-struct-statvfs-stand-for
        );
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
                    reply.error(e.raw_os_error().unwrap());
                    return;
                }
            };
            let meta = file.metadata().expect("already called, so should work");
            self.ino_paths.insert(meta.ino(), path);
            let fd = self.register_new_file(file);
            reply.created(
                &std::time::Duration::ZERO,
                &(&meta).into(),
                0,
                fd as _,
                flags as _,
            )
        } else {
            log::error!("Failed to create file {:?} with errno {:?}", name, errno());
            reply.error(errno());
        }
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
}
