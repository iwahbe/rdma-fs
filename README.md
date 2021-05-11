## RDMA Filesystem Over FUSE
Ian Wahbe

### Background <!-- (1--2 pages) -->

--- 

Hardware accelerators have evolved from small network and cryptography chips
to full blown separate computers. As these accelerator computers are still
subservient to the host computer, it's important there is easy and fast
communication between host and accelerator. This can be accomplished via message
passing over an internal network, where each process on the accelerator talks
directly to a corresponding process on the host. This leads to extremely tight
coupling, where each host and accelerator need custom message passing software
written to interface between them. Because that accelerators are usually the
slower general computer, most data is kept on the host, or an external drive
connected to the host. To avoid this, I provide a base system to intermediate
between host and accelerator. Using the Linux philosophy of "everything is a
file", I have written a file system mirror that allows an accelerator to read
and write to the host file system over the network. 

I build my file system mirror on two new and distinct pieces of technology. 

#### FUSE (Filesystem in Userspace) 
FUSE provides a generic kernel extension, and an interaction library written in
C (I used a Rust wrapper). Without writing my own kernal extension, this is the
only way to allow my filesystem to be completely transparent to the user once
mounted.

#### RDMA (remote direct memory access)
RDMA provides the low latency communication of data, especially buffer reads and
writes. I use RDMA's memory region abstraction, which allows the the host and
accelerator to share (with minimal overhead) a region of memory over the
network. This has the advantage of not requiring a system call to exchange
information. Instead, RDMA uses a queue system. Each call to send the memory
region is deposited in a device specific queue, and eventually sent by the OS.
Likewise, we receive from looking at a queue maintained by the OS (holding
incoming memory writes). To read or write data from the memory region, you can
just dereference the pointer to it, and pretend its backed by normal memory. I
found some similarity between RDMA and working with memory mapped files.

Because RDMA does not use the standard network abstractions, it requires special
hardware and software to use. I run RDMA over a 25g cable between our Nvidia
Bluefield network card and the host machine (chimera), with both running linux.
It requires configuration of the devices at both ends, as well as a kernel
extension to handle the queues.

Finally, RDMA has a major drawback. Unlike standard network connections, which
use `port`s to virtualize their address space, RDMA hooks directly into its
supporting hardware. This means we are restricted to a single connection at a
time per RDMA device. While some cards and chips can have multiple devices, it
stills supports a distinctly limited number of connections.


<!-- Problem description and motivation -->
<!-- Relationship to the hardware used -->
<!-- Any background material on relevant past work -->

### Proposed Solution <!-- (~2 pages) -->

---

I built a transparent filesystem that operates over RDMA. When I say
transparent, I meant that to the host, it looks like a server is accessing all
files the client is accessing, and most difficult operations are performed on
the host's native file system. For the client, I use FUSE to prevent the user
from experiencing any difference in usage.


#### Design considerations and choices for your implementation 
The technology choices I made stemmed from two main decisions. I needed to use
FUSE and RDMA, and I wanted to write my project in Rust. There exists only 1
maintained interface to FUSE for Rust, called
[fuser](https://github.com/cberner/fuser) (FUSE Rust), which I used. You provide
it a `struct` with an initialization method, teardown method, and methods that
encompass the operations your file system supports. The signature of all methods
look similar. The function takes as arguments its input, and reply is a `struct`
with methods to take either output or errors. An example method, `open`, looks
like this:

``` rust
    fn open(&mut self, req: &Request<'_>, ino: Ino, flags: i32, reply: ReplyOpen) {
        // either
        reply.opened(file_handle, open_flags);
        // or
        reply.error(ERROR_NUMBER);
    }
```

---

I needed to pair this with a RDMA library. I chose
[ibverbs](https://github.com/jonhoo/rust-ibverbs). It provided a solid set of
abstractions for RDMA, but usage details are too complicated to go into here.
Most of the finicky RDMA work was done in `rdma-fuse/src/lib.rs`, and is
available for closer inspection.

After library and language were chosen, most design decisions were made. I then
proceeded to fill in the methods as required.

#### Overview of algorithms / code / implementation 

Given FUSE, the main design followed. I built a server that sat on the host
(chimera), and a client that runs on the accelerator. They begin by generating a
TCP connection, which is used to initiate a RDMA handshake. After that, all
communication occurs by reading and writing to the fixed size buffer. We store a
fixed size `enum` (tagged union), and read the tag to determine which operation
is requested. Each payload contains the information for both a request and a
reply, allowing the client to validate it's reply and allowing the server to
perform minimal writes to shared memory. Each message corresponds to a file
system syscall, and thus a FUSE request (except `Exit` and `Null`). When
received by the server, it responds with an associated method on the `LocalData`
`struct`. The client gets the response, unpacks it, and replies with the data
given more or less blindly.

The communication `enum` as declared goes as follows:

``` rust
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

    Open {
        errno: Option<i32>,
        ino: Ino,
        flags: i32,
        fh: Fh,
        open_flags: u32,
    },

    Release {
        errno: Option<i32>,
        ino: Ino,
        fh: Fh,
    },

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
```

We can describe the system as follows:

<!-- I know this is not JSON, but it prevents markdown from trying to guess highlights. -->
```json

 +----------+                +----------+
 |  RDMA(H) | <------------> |  RDMA(C) |
 +----------+                +----------+
      |                           |
      |                           |
+-----------+               +------------+
|  HOST FS  |               |  CLIENT FS |
+-----------+               +------------+
```

Only the host side stores state. The client only remembers what type of call it
is currently executing, and that is maintained by program staci.


#### Similar Systems

This sounds a lot like NFS, but is importantly different. Because the goal is
for computers who are write next to each other to communicate, instead of a
generic and fallable 1-N pairing, I can operate much more efficiently then NFS.
Because this is a modern system, I take advantage of RDMA as my message passing
interface. This both reduces latency, and the overhead. It does have major
downsides compared to NFS as well.


<!-- Design considerations and choices for your implementation -->
<!-- Overview of algorithms / code / implementation -->
<!-- Description of dependencies, prerequisites, and technical constraints -->
<!-- Links to source code and libraries -->
<!-- Use a visualization or diagram if helpful to understand the technical concepts -->

### Evaluation <!-- (~2 pages) -->

---

<!-- Workloads and environment used for evaluation -->
<!-- Reproduction instructions -->
<!-- Performance results, as figures or tables -->
<!-- Comparison to any other known results -->

### Conclusion

---

<!-- Summary of findings and experience working on this project -->
<!-- Future work and “wish list” items -->

