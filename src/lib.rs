#![feature(pin_static_ref)]
#![feature(try_blocks)]
#![feature(option_result_unwrap_unchecked)]

mod file;
mod local;
mod remote;

pub use local::LocalMount;
pub use remote::{remote_server, RDMAFs, RDMA_MESSAGE_BUFFER_SIZE};

use bincode;
use ibverbs::{CompletionQueue, Context, MemoryRegion, ProtectionDomain, QueuePair};
use std::mem::transmute;
use std::pin::Pin;
use std::{io, ops::Deref};
use std::{
    io::{Read, Write},
    ops::DerefMut,
};

pub type Ino = u64;
pub type Fh = u64;

pub struct RDMAConnection<T>
where
    T: Copy + Default,
{
    // This is unsafe as f**k
    // We need the fields to drop in this order to avoid ub
    //
    // To ensure that our static pointers remain valid, we pin them. This should
    // prevent the rust runtime from moving them when they mutate themselves.
    mem: MemoryRegion<T>,
    qp: QueuePair<'static>,
    _pd: Pin<Box<ProtectionDomain<'static>>>,
    cq: Pin<Box<CompletionQueue<'static>>>,
    _ctx: Pin<Box<Context>>,
    next_id: u64,
}

impl<T> RDMAConnection<T>
where
    T: Copy + Default,
{
    // Creates a new `RDMAConnection`. This is a wrapper around a
    // `MemoryRegion<T>`, with all the context needed to read and write to it.
    pub fn new<W>(size: usize, mut connection: W) -> io::Result<Self>
    where
        W: Read + Write,
    {
        let ctx: Pin<Box<Context>> = Box::pin(unsafe {
            transmute(
                ibverbs::devices()?
                    .iter()
                    .next()
                    .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?
                    .open()?,
            )
        });

        // Unsafe: We cast the lifetime to static. This is safe because we embed
        // this all in the same struct. The struct garentees the drop order to
        // be correct.
        let cq: Pin<Box<CompletionQueue<'static>>> =
            Box::pin(unsafe { transmute(ctx.as_ref().create_cq(16, 0)?) });
        let pd: Pin<Box<ProtectionDomain<'static>>> = Box::pin(unsafe {
            transmute(
                ctx.alloc_pd()
                    .map_err(|_| io::Error::from(io::ErrorKind::AddrNotAvailable))?,
            )
        });

        let qp_builder = unsafe {
            let cq: &'static CompletionQueue = &*(&*cq as *const CompletionQueue);
            transmute::<_, &'static ProtectionDomain<'static>>(pd.as_ref())
                .create_qp(cq, cq, ibverbs::ibv_qp_type::IBV_QPT_RC)
                .build()?
        };

        let qp = {
            let endpoint = qp_builder.endpoint();
            let encode: Vec<u8> = bincode::serialize(&endpoint).unwrap();
            connection.write_all(&encode)?;
            let endpoint: ibverbs::QueuePairEndpoint =
                bincode::deserialize_from(&mut connection).unwrap();
            qp_builder.handshake(endpoint)?
        };

        let mem = pd.allocate::<T>(size)?;

        Ok(RDMAConnection {
            cq,
            _ctx: ctx,
            _pd: pd,
            qp,
            mem,
            next_id: 0,
        })
    }

    pub unsafe fn send_sized(&mut self, size: usize) -> io::Result<()> {
        let id = self.next_id;
        self.next_id += 1;
        // Unsafe: we perform the unsafe send. This is safe because `self.mem`
        // is a correctly configured memory region. It is up to the sender to
        // ensure that recieve is called.
        self.qp.post_send(&mut self.mem, ..size, id)?;
        self.complete(id)
    }

    // Send the entire buffer back.
    pub fn send(&mut self) -> io::Result<()> {
        unsafe { self.send_sized(self.mem.len()) }
    }

    /// Recieve a left aligned block of length `size`. The caller is responcible
    /// for garenteing that the data read from the memory region is valid if
    /// only `size` bytes are written to it.
    pub unsafe fn recv_sized(&mut self, size: usize) -> io::Result<()> {
        let id = self.next_id;
        self.next_id += 1;
        // Unsafe: It is up the caller to ensure that `complete` is called at
        // the other end.
        self.qp.post_receive(&mut self.mem, ..size, id)?;
        self.complete(id)
    }

    // recieve on the buffer.
    pub fn recv(&mut self) -> io::Result<()> {
        unsafe { self.recv_sized(self.mem.len()) }
    }

    // Waits on the completion of a send or recieve with a matching `id`.
    fn complete(&mut self, id: u64) -> io::Result<()> {
        let mut completions = [ibverbs::ibv_wc::default(); 16];
        loop {
            let completed = self
                .cq
                .poll(&mut completions[..])
                .map_err(|_| io::Error::from(io::ErrorKind::Interrupted))?;
            for wr in completed {
                if wr.wr_id() == id {
                    return Ok(());
                }
            }
        }
    }
}

impl<T> Deref for RDMAConnection<T>
where
    T: Copy + Default,
{
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.mem
    }
}

impl<T> DerefMut for RDMAConnection<T>
where
    T: Copy + Default,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.mem
    }
}
