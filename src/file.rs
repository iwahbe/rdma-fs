use crate::Fh;
use memmap2;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::{fs, io};

#[derive(Debug)]
pub struct OpenFile {
    memory: Option<memmap2::MmapMut>,
    file: fs::File,
    len: u64,
    fh: Fh,
}

#[derive(Copy, Clone, Debug)]
pub struct FileBuilder {
    create: bool,
    read: bool,
    write: bool,
    trunc: bool,
}

impl FileBuilder {
    pub fn new() -> Self {
        Self {
            create: false,
            read: false,
            write: false,
            trunc: false,
        }
    }

    pub fn create(mut self, create: bool) -> Self {
        self.create = create;
        self
    }

    pub fn read(mut self, read: bool) -> Self {
        self.read = read;
        self
    }

    pub fn write(mut self, write: bool) -> Self {
        self.write = write;
        self
    }

    /// Setts the flag to O_TRUNC
    pub fn trunc(mut self, trunc: bool) -> Self {
        self.trunc = trunc;
        self
    }

    /// Build a set of open flags from C flags
    pub fn from_flags(flags: i32) -> Self {
        use libc::*;
        Self::new()
            .read(flags & O_RDONLY != 0)
            .write(flags & O_WRONLY != 0)
            .create(flags & O_CREAT != 0)
            .trunc(flags & O_TRUNC != 0)
    }

    /// Creates a new openfile from unix flags
    pub fn path(self, path: &Path) -> io::Result<OpenFile> {
        let file = fs::OpenOptions::new()
            .truncate(self.trunc)
            .read(self.read)
            .write(self.write)
            .create(self.create)
            .open(path)?;
        let meta = file.metadata()?;
        let fh = meta.ino() as _;
        Ok(OpenFile {
            memory: None,
            len: meta.len(),
            file,
            fh,
        })
    }
}

impl OpenFile {
    pub fn metadata(&self) -> io::Result<fs::Metadata> {
        self.file.metadata()
    }

    /// Truncate the file to size. size can be larger or smaller then the
    /// previous file size.
    pub fn truncate(&mut self, size: u64) -> io::Result<()> {
        self.memory.take();
        let trunc = self.file.set_len(size);
        if trunc.is_err() {
            log::error!("Failed to truncate on fh {:?}", self.fh);
            trunc?
        }
        self.len = size;
        Ok(())
    }

    // Expose a unique file handle
    pub fn fh(&self) -> Fh {
        self.fh
    }

    /// Get a reference to the backing memory.
    fn get_map(&mut self) -> io::Result<&mut memmap2::MmapMut> {
        log::info!("Get map was called on file {:?}", self.fh);
        if self.memory.is_none() {
            let meta = self.file.metadata()?;
            self.len = meta.len();
            assert!(meta.len() > 0, "mmaped files must have positive length");
            self.memory = Some(unsafe {
                match memmap2::MmapOptions::new().map_mut(&self.file) {
                    Ok(k) => k,
                    Err(e) => {
                        log::error!(
                            "Failed to mmap file {:?} with error {}. File size is {}",
                            self.fh,
                            e,
                            meta.len()
                        );
                        return Err(e);
                    }
                }
            });
        }
        Ok(self.memory.as_mut().unwrap())
    }

    pub fn write(&mut self, buf: &[u8], offset: i64) -> io::Result<usize> {
        if buf.len() == 0 {
            return Ok(0);
        }
        if buf.len() as u64 + offset as u64 >= self.len {
            self.truncate(buf.len() as u64 + offset as u64 + 1)?;
        }
        let map = self.get_map()?;
        assert!(
            map.len() as usize > offset as usize + buf.len(),
            "We can't write off the end of a file"
        );
        unsafe {
            let map: *mut u8 = map.as_mut_ptr().offset(offset as _);
            std::ptr::copy_nonoverlapping(buf.as_ptr(), map, buf.len())
        };
        Ok(buf.len())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        if let Some(mem) = self.memory.as_mut() {
            mem.flush()?;
        }
        Ok(())
    }
    pub fn read(&mut self, buf: &mut [u8], offset: i64, size: usize) -> io::Result<usize> {
        if self.len == 0 {
            return Ok(0);
        }
        let map = self.get_map()?;
        let remainder = if map.len() >= offset as usize {
            map.len() - offset as usize
        } else {
            0
        };
        let map_size = buf.len().min(remainder).min(size);
        unsafe {
            std::ptr::copy_nonoverlapping(
                map.as_ptr().offset(offset as _),
                buf.as_mut_ptr(),
                map_size,
            );
        }
        Ok(map_size)
    }
}
