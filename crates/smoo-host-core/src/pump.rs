use crate::{Transport, TransportError, TransportErrorKind, TransportResult};
use alloc::{collections::VecDeque, format, vec::Vec};
use core::{future::Future, pin::Pin, task::{Context, Poll}};
use futures_channel::{mpsc, oneshot};
use futures_util::{
    future::{BoxFuture, Fuse, FusedFuture, FutureExt, OptionFuture},
    select_biased,
    stream::StreamExt,
};
use smoo_proto::{Request, Response, REQUEST_LEN, RESPONSE_LEN};

/// Stream of Requests produced by the pump.
pub type HostIoPumpRequestRx = mpsc::UnboundedReceiver<Request>;

/// Handle used by workers to issue bulk + interrupt OUT operations through the pump.
#[derive(Clone)]
pub struct HostIoPumpHandle {
    cmd_tx: mpsc::UnboundedSender<PumpCmd>,
}

/// Future that drives the pump. Callers should spawn this on their executor of choice.
pub struct HostIoPumpTask {
    inner: BoxFuture<'static, TransportResult<()>>,
}

impl Future for HostIoPumpTask {
    type Output = TransportResult<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().inner.as_mut().poll(cx)
    }
}

/// Start the host I/O pump.
///
/// Returns a handle for issuing commands, a request receiver for incoming Requests, and a pump
/// future that must be spawned by the caller.
pub fn start_host_io_pump<T>(transport: T) -> (HostIoPumpHandle, HostIoPumpRequestRx, HostIoPumpTask)
where
    T: Transport + Clone + Send + Sync + 'static,
{
    let (cmd_tx, cmd_rx) = mpsc::unbounded();
    let (req_tx, req_rx) = mpsc::unbounded();
    let task = HostIoPumpTask {
        inner: run_pump(transport, cmd_rx, req_tx).boxed(),
    };
    (HostIoPumpHandle { cmd_tx }, req_rx, task)
}

impl HostIoPumpHandle {
    /// Send a Response over interrupt OUT.
    pub async fn send_response(&self, response: Response) -> TransportResult<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.send_cmd(PumpCmd::SendResponse { response, reply: reply_tx })
            .await?;
        reply_rx.await.unwrap_or_else(|_| Err(disconnected_err()))
    }

    /// Read a bulk payload of `len` bytes from the gadget.
    pub async fn read_bulk(&self, len: usize) -> TransportResult<Vec<u8>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.send_cmd(PumpCmd::ReadBulk {
            buf: vec![0u8; len],
            reply: reply_tx,
        })
        .await?;
        reply_rx.await.unwrap_or_else(|_| Err(disconnected_err()))
    }

    /// Write a bulk payload to the gadget.
    pub async fn write_bulk(&self, buf: Vec<u8>) -> TransportResult<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.send_cmd(PumpCmd::WriteBulk { buf, reply: reply_tx })
            .await?;
        reply_rx.await.unwrap_or_else(|_| Err(disconnected_err()))
    }

    /// Request a graceful pump shutdown.
    pub async fn shutdown(&self) -> TransportResult<()> {
        self.cmd_tx
            .unbounded_send(PumpCmd::Shutdown)
            .map_err(|_| disconnected_err())
    }

    async fn send_cmd(&self, cmd: PumpCmd) -> TransportResult<()> {
        self.cmd_tx
            .unbounded_send(cmd)
            .map_err(|_| disconnected_err())
    }
}

enum PumpCmd {
    SendResponse {
        response: Response,
        reply: oneshot::Sender<TransportResult<()>>,
    },
    ReadBulk {
        buf: Vec<u8>,
        reply: oneshot::Sender<TransportResult<Vec<u8>>>,
    },
    WriteBulk {
        buf: Vec<u8>,
        reply: oneshot::Sender<TransportResult<()>>,
    },
    Shutdown,
}

struct InterruptOutOp {
    response: Response,
    reply: oneshot::Sender<TransportResult<()>>,
}

struct BulkInOp {
    buf: Vec<u8>,
    reply: oneshot::Sender<TransportResult<Vec<u8>>>,
}

struct BulkOutOp {
    buf: Vec<u8>,
    reply: oneshot::Sender<TransportResult<()>>,
}

type InterruptInFuture = Fuse<OptionFuture<BoxFuture<'static, TransportResult<Request>>>>;
type InterruptOutFuture = Fuse<OptionFuture<BoxFuture<'static, InterruptOutResult>>>;
type BulkInFuture = Fuse<OptionFuture<BoxFuture<'static, BulkInResult>>>;
type BulkOutFuture = Fuse<OptionFuture<BoxFuture<'static, BulkOutResult>>>;

type InterruptOutResult = (oneshot::Sender<TransportResult<()>>, TransportResult<()>);
type BulkInResult = (oneshot::Sender<TransportResult<Vec<u8>>>, TransportResult<Vec<u8>>);
type BulkOutResult = (oneshot::Sender<TransportResult<()>>, TransportResult<()>);

async fn run_pump<T>(
    transport: T,
    cmd_rx: mpsc::UnboundedReceiver<PumpCmd>,
    req_tx: mpsc::UnboundedSender<Request>,
) -> TransportResult<()>
where
    T: Transport + Clone + Send + Sync + 'static,
{
    let mut cmd_rx = cmd_rx.fuse();
    let mut next_cmd = cmd_rx.next().fuse();
    let mut interrupt_in: InterruptInFuture = arm_interrupt_in(transport.clone());
    let mut interrupt_out: InterruptOutFuture = OptionFuture::from(None).fuse();
    let mut bulk_in: BulkInFuture = OptionFuture::from(None).fuse();
    let mut bulk_out: BulkOutFuture = OptionFuture::from(None).fuse();
    let mut interrupt_out_queue: VecDeque<InterruptOutOp> = VecDeque::new();
    let mut bulk_in_queue: VecDeque<BulkInOp> = VecDeque::new();
    let mut bulk_out_queue: VecDeque<BulkOutOp> = VecDeque::new();
    let mut cmd_closed = false;

    loop {
        if interrupt_in.is_terminated() {
            interrupt_in = arm_interrupt_in(transport.clone());
        }
        if interrupt_out.is_terminated() {
            if let Some(op) = interrupt_out_queue.pop_front() {
                interrupt_out = arm_interrupt_out(transport.clone(), op);
            }
        }
        if bulk_in.is_terminated() {
            if let Some(op) = bulk_in_queue.pop_front() {
                bulk_in = arm_bulk_in(transport.clone(), op);
            }
        }
        if bulk_out.is_terminated() {
            if let Some(op) = bulk_out_queue.pop_front() {
                bulk_out = arm_bulk_out(transport.clone(), op);
            }
        }

        select_biased! {
            cmd = next_cmd => {
                next_cmd = cmd_rx.next().fuse();
                match cmd {
                    Some(PumpCmd::SendResponse { response, reply }) => {
                        interrupt_out_queue.push_back(InterruptOutOp { response, reply });
                    }
                    Some(PumpCmd::ReadBulk { buf, reply }) => {
                        bulk_in_queue.push_back(BulkInOp { buf, reply });
                    }
                    Some(PumpCmd::WriteBulk { buf, reply }) => {
                        bulk_out_queue.push_back(BulkOutOp { buf, reply });
                    }
                    Some(PumpCmd::Shutdown) => break Ok(()),
                    None => cmd_closed = true,
                }
            }
            req = interrupt_in => {
                match req {
                    Some(Ok(request)) => {
                        if req_tx.unbounded_send(request).is_err() {
                            break Err(disconnected_err());
                        }
                    }
                    Some(Err(err)) => break Err(err),
                    None => {}
                }
            }
            res = interrupt_out => {
                if let Some((reply, result)) = res {
                    let _ = reply.send(result);
                }
            }
            res = bulk_in => {
                if let Some((reply, result)) = res {
                    let _ = reply.send(result);
                }
            }
            res = bulk_out => {
                if let Some((reply, result)) = res {
                    let _ = reply.send(result);
                }
            }
            default => {
                if cmd_closed
                    && interrupt_out_queue.is_empty()
                    && bulk_in_queue.is_empty()
                    && bulk_out_queue.is_empty()
                    && interrupt_out.is_terminated()
                    && bulk_in.is_terminated()
                    && bulk_out.is_terminated()
                {
                    break Ok(());
                }
            }
        }
    }
}

fn arm_interrupt_in<T>(transport: T) -> InterruptInFuture
where
    T: Transport + Clone + Send + Sync + 'static,
{
    OptionFuture::from(Some(async move {
        let mut buf = [0u8; REQUEST_LEN];
        let len = transport.read_interrupt(&mut buf).await?;
        if len != REQUEST_LEN {
            return Err(protocol_error(format!(
                "request transfer truncated (expected {REQUEST_LEN}, got {len})"
            )));
        }
        Request::decode(buf).map_err(|err| protocol_error(format!("decode request: {err}")))
    }
    .boxed()))
    .fuse()
}

fn arm_interrupt_out<T>(transport: T, op: InterruptOutOp) -> InterruptOutFuture
where
    T: Transport + Clone + Send + Sync + 'static,
{
    OptionFuture::from(Some(async move {
        let data = op.response.encode();
        let reply = op.reply;
        let result = match transport.write_interrupt(&data).await {
            Ok(len) if len == RESPONSE_LEN => Ok(()),
            Ok(len) => Err(protocol_error(format!(
                "response transfer truncated (expected {RESPONSE_LEN}, wrote {len})"
            ))),
            Err(err) => Err(err),
        };
        (reply, result)
    }
    .boxed()))
    .fuse()
}

fn arm_bulk_in<T>(transport: T, op: BulkInOp) -> BulkInFuture
where
    T: Transport + Clone + Send + Sync + 'static,
{
    OptionFuture::from(Some(async move {
        let mut buf = op.buf;
        let reply = op.reply;
        let len = transport.read_bulk(&mut buf).await;
        let result = match len {
            Ok(read) if read == buf.len() => Ok(buf),
            Ok(read) => Err(protocol_error(format!(
                "bulk read truncated (expected {}, got {read})",
                buf.len()
            ))),
            Err(err) => Err(err),
        };
        (reply, result)
    }
    .boxed()))
    .fuse()
}

fn arm_bulk_out<T>(transport: T, op: BulkOutOp) -> BulkOutFuture
where
    T: Transport + Clone + Send + Sync + 'static,
{
    OptionFuture::from(Some(async move {
        let reply = op.reply;
        let len = op.buf.len();
        let result = match transport.write_bulk(&op.buf).await {
            Ok(written) if written == len => Ok(()),
            Ok(written) => Err(protocol_error(format!(
                "bulk write truncated (expected {len}, wrote {written})"
            ))),
            Err(err) => Err(err),
        };
        (reply, result)
    }
    .boxed()))
    .fuse()
}

fn protocol_error(message: impl Into<String>) -> TransportError {
    TransportError::with_message(TransportErrorKind::Protocol, message)
}

fn disconnected_err() -> TransportError {
    TransportError::with_message(
        TransportErrorKind::Disconnected,
        "pump not running",
    )
}
