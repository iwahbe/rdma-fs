## FUSE Filesystem Over RDMA

Completed for Reed's Topics in Systems class. Professor is [Eitan Frachtenberg](https://www.reed.edu/faculty-profiles/profiles/frachtenberg-eitan.html).

Ian Wahbe

### Warning

This is not a stable system and should not be used in production. All software
is provided as is and without warranty.

### Building

The program should compile fine with `cargo build`. It does need rust's nightly
compiler and fuser header files.

### Background <!-- (1-2 pages) -->

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
C (I used a Rust wrapper). Without writing my own kernel extension, this is the
only way to allow my filesystem to be completely transparent to the user once
mounted.

#### RDMA (remote direct memory access)

RDMA provides the low latency communication of data, especially buffer reads and
writes. I use RDMA's memory region abstraction, which allows the host and
accelerator to share (with minimal overhead) a region of memory over a local
network. This has the advantage of not requiring a system call to exchange
information. Instead, RDMA uses a queue system. Each call to send the memory
region is deposited in a device specific queue, and eventually sent by the OS.
Likewise, we receive message by looking at a queue maintained by the OS (holding
incoming memory writes). To read or write data from the memory region, you can
just dereference the pointer to it, and treat the memory region as an allocated
array. I found some similarity between RDMA and
working with memory mapped files.

Because RDMA does not use the standard network abstractions, it requires special
hardware and software to use. I run RDMA over a 25 GB cable between our Nvidia
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

```rust
    fn open(&mut self, req: &Request<'_>, ino: Ino, flags: i32, reply: ReplyOpen) {
        // either
        reply.opened(file_handle, open_flags);
        // or
        reply.error(ERROR_NUMBER);
    }
```

---

I needed to pair this with an RDMA library. I chose
[ibverbs](https://github.com/jonhoo/rust-ibverbs). It provided a solid set of
abstractions for RDMA, but usage details are too complicated to go into here.
Most of the finicky RDMA work was done in `rdma-fuse/src/lib.rs`, and is
available for closer inspection.

After library and language were chosen, most design decisions were made. I then
proceeded to fill in the methods as required.

#### Overview of algorithms / code / implementation

Given FUSE, the main design followed. I built a server that sat on the host
(chimera), and a client that runs on the accelerator. They begin by generating a
TCP connection, which is used to initiate an RDMA handshake. After that, all
communication occurs by reading and writing to the fixed size buffer. We store a
fixed size `enum` (tagged union), and read the tag to determine which operation
is requested. Each payload contains the information for both a request and a
reply, allowing the client to validate its reply and allowing the server to
perform minimal writes to shared memory. Each message corresponds to a file
system syscall, and thus a FUSE request (except `Exit` and `Null`). When
received by the server, it responds with an associated method on the `LocalData`
`struct`. The client gets the response, unpacks it, and replies with the data
given more or less blindly.

The communication `enum` as declared goes as follows:

```rust
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
is currently executing, and that is maintained by program stack.

#### Similar Systems

This sounds a lot like NFS, but is importantly different. Because the goal is to
facilitate communication for computers which are directly adjacent (or attached)
to each other, instead of a generic and fallable 1-N pairing, I can operate much
more efficiently then NFS. Because this is a modern system, I take advantage of
RDMA as my message passing interface. This both reduces latency, and the
overhead. It does have major downsides compared to NFS as well.

##### Running

To actually use the system, we do the following:

```sh
# on the host
~/x86/bin/rdma-fuse remote --host target/ --ip 192.168.100.1:8393
# on the client
~/arm/bin/rdma-fuse remote --client mnt/ --ip 192.168.100.1:8393
```

This mounts `target` on the host system to the empty folder `mnt` on the client
system. It uses ip address `192.168.100.1` to communicate with port `8393`.
Detailed usage information can be found by typing `rdma-fuse help`.

<!-- Design considerations and choices for your implementation -->
<!-- Overview of algorithms / code / implementation -->
<!-- Description of dependencies, prerequisites, and technical constraints -->
<!-- Links to source code and libraries -->
<!-- Use a visualization or diagram if helpful to understand the technical concepts -->

### Evaluation <!-- (~2 pages) -->

---

When evaluating the system, we compare it with two other cases. Eitan has
mirrored the home folder of chimera on `bf1`, so we test that system, the native
file system. These provide comparison for the RDMA system. I perform the tests
using the `fs-bench` test provided by
[ltp](https://github.com/linux-test-project/ltp.git). I have removed the
ownership components of the test, as my RDMA/FUSE implementation does not
support ownership. The linux test project contains instructions to build and run
its tests. `fs-bench` is in `testcases/kernel/fs`, and contains its own
instructions.

`fs-bench` has four phases:

1. It creates files until the file system is out of memory.
2. It randomly accesses the files it creates.
3. It deletes and creates randomly.
4. It deletes all files it created.

I modified the default test, removing changing the file owners between stages.
My implementation does not support changing ownership of files. Running a
benchmark is done simply with a command like this one:

```sh
ianwahbe@bf1:/ltp-arm/testcases/kernel/fs/fs-bench/mnt$ ../fs-benchmark.sh |& tee ../result.txt
```

I ran the test on the all three systems, as well as an internal chimera with rdma.

|                      | chimera       | chimera rdma         | bf1          | chimera bf1 rdma     |
| -------------------- | ------------- | -------------------- | ------------ | -------------------- |
| technology           | native fs     | rdma (same computer) | native fs    | rdma (bf1 - chimera) |
| create files         | 2270277/8m45s | 2283047/10m8s        | 58123/2m33s  | 57420/4m49s          |
| random access        | 564363/1m45s  | 564272/1m45s         | 10452/0m0.6s | 10459/0m8s           |
| random create/delete | 250119/1m9s   | 250289/1m6s          | 4555/3m2s    | 4523/0m29s           |
| remove               | 0m19s         | 0m18s                | 0m13s        | 0m11s                |
| total                | 25m24s        | 26m50s               | 6m12s        | 10m38s               |

I also attempted to run `fs-bench` over `NFS` as it was already installed. After
an hour, NFS failed, and the benchmark started returning errors.

I draw 2 conclusions from this data.

1. That FUSE and RDMA impose a roughly 10% cost over directly using the build in
   file system. We see this from comparing `chimera` and `chimera rdma`. This is
   latency from the system itself, not from data transfer.
2. There is a 90% increase cost from transferring the data back and forth
   between host and client. A rough doubling makes sense. Data needs to be moved
   from the input buffer (managed by FUSE), to an RDMA buffer. It is then sent to
   the host computer, copied into a memory mapped file, and a confirmation is
   sent back. This means that any read and write must occur twice.

<!-- Workloads and environment used for evaluation -->
<!-- Reproduction instructions -->
<!-- Performance results, as figures or tables -->
<!-- Comparison to any other known results -->

### Conclusion

---

I successfully implemented a file system mirroring system that operates over
RDMA. It is incomparably fast versus NFS. I measured the results, and provide a
replicable test. While the system is solid, it could be further optimized. Every
RDMA communication exchanges a full buffer of size `READ_WRITE_BUFFER_SIZE`
(8192). I would like to extend the system, to only exchange the necessary amount
of space. There are also missing capabilities, like permissions and soft links.

<!-- Summary of findings and experience working on this project -->
<!-- Future work and “wish list” items -->
