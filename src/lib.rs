#![feature(pin_static_ref)]
#![feature(try_blocks)]
#![feature(duration_zero)]
#![feature(option_result_unwrap_unchecked)]

mod local;
mod remote;

pub use local::LocalMount;

use bincode;
use ibverbs::{CompletionQueue, Context, MemoryRegion, ProtectionDomain, QueuePair};
use std::io;
use std::io::{Read, Write};
use std::mem::transmute;
use std::pin::Pin;

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
                    .ok_or(io::Error::from(io::ErrorKind::NotFound))?
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
                    transmute(&cq),
                    transmute(&cq),
                    ibverbs::ibv_qp_type::IBV_QPT_RC,
                )
                .build()?
        };

        let qp = {
            let endpoint = qp_builder.endpoint();
            let encode: Vec<u8> = bincode::serialize(&endpoint).unwrap();
            connection.write(&encode)?;
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
        })
    }
}
