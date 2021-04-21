#![feature(pin_static_ref)]
#![feature(try_blocks)]
#![feature(duration_zero)]
#![feature(option_result_unwrap_unchecked)]

mod local;
mod remote;

pub use local::LocalMount;

use bincode;
use ibverbs::{CompletionQueue, Context, MemoryRegion, ProtectionDomain, QueuePair};
use std::mem::transmute;
use std::pin::Pin;
use std::{io, ops::Deref};
use std::{
    io::{Read, Write},
    ops::DerefMut,
};

struct RDMAConnection<T>
where
    T: Copy + Default,
{
    // This is unsafe as f**k
    // We need the fields to drop in this order to avoid ub
    pub mem: MemoryRegion<T>,
    pub qp: QueuePair<'static>,
    pd: Pin<Box<ProtectionDomain<'static>>>,
    cq: Pin<Box<CompletionQueue<'static>>>,
    ctx: Pin<Box<Context>>,
    next_id: u64,
}

impl<T> RDMAConnection<T>
where
    T: Copy + Default,
{
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
        let cq: Pin<Box<CompletionQueue<'static>>> =
            Box::pin(unsafe { transmute(ctx.as_ref().create_cq(16, 0)?) });
        let pd: Pin<Box<ProtectionDomain<'static>>> = Box::pin(unsafe {
            transmute(
                ctx.alloc_pd()
                    .map_err(|_| io::Error::from(io::ErrorKind::AddrNotAvailable))?,
            )
        });

        let qp_builder = unsafe {
            transmute::<_, &'static ProtectionDomain<'static>>(pd.as_ref())
                .create_qp(
                    &*(&cq as *const _ as *const CompletionQueue),
                    &*(&cq as *const _ as *const CompletionQueue),
                    ibverbs::ibv_qp_type::IBV_QPT_RC,
                )
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
            ctx,
            pd,
            qp,
            mem,
            next_id: 0,
        })
    }

    fn send(&mut self) -> io::Result<()> {
        unsafe { self.qp.post_send(&mut self.mem, .., self.next_id)? }
        self.next_id += 1; // TODO: what was I doing with `self.next_id`
        Ok(())
    }

    fn recv(&mut self) -> io::Result<()> {
        unsafe { self.qp.post_receive(&mut self.mem, .., self.next_id) }
    }
}

impl<T> Deref for RDMAConnection<T>
where
    T: Copy + Default,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.mem[0]
    }
}

impl<T> DerefMut for RDMAConnection<T>
where
    T: Copy + Default,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.mem[0]
    }
}
