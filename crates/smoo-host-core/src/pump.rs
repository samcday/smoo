//! Pipelined host-side I/O pump.
//!
//! Splits the data path into four cooperating sub-futures, joined inside a
//! single `run` future so the pump stays executor-agnostic — it works
//! under tokio for the native CLI and `wasm-bindgen-futures` for the web
//! worker without spawning anything itself.
//!
//! Consumer model: drive [`RequestRx`] in a single dispatcher loop. For
//! each Request, decide whether bulk-IN data is needed; if so, call
//! [`HostPumpHandle::queue_bulk_in_read`] *from the dispatcher loop*
//! before handing the resulting [`BulkInHandle`] to a per-Request
//! handler. Multiple handlers may run concurrently (e.g. driven by
//! `FuturesUnordered`), each calling
//! [`HostPumpHandle::send_response_with_bulk`] when its work is done.
//! Responses MAY be written out-of-order; bulk-OUT order on the wire
//! follows Response order on interrupt OUT (per HACKING.md §4) and is
//! preserved by `interrupt_out_writer` enqueuing the bulk payload behind
//! the corresponding Response.
//!
//! The bulk-IN ordering invariant — bulk-IN payloads on the wire must
//! arrive in the order their Requests hit interrupt IN — is enforced by
//! `bulk_in_worker` draining a single FIFO. The dispatcher is responsible
//! for calling `queue_bulk_in_read` in Request arrival order; documenting
//! that contract is the cost we pay for making this otherwise simple.
//!
//! Sub-futures (joined inside `run`):
//! - `interrupt_in_reader` reads Requests off interrupt IN and forwards
//!   them on `RequestRx`.
//! - `interrupt_out_writer` drains [`PumpCmd`]s; writes the Response on
//!   interrupt OUT and, for non-empty `bulk_out`, pushes a
//!   [`BulkOutPending`] entry behind it. Acks the consumer once the
//!   Response is on the wire so the handler is freed; the bulk write
//!   completes concurrently in `bulk_out_worker`.
//! - `bulk_in_worker` drains the bulk-IN FIFO populated by
//!   `queue_bulk_in_read`, reads `byte_len` bytes off bulk IN, and
//!   delivers them via the per-entry oneshot.
//! - `bulk_out_worker` drains the bulk-OUT FIFO populated by
//!   `interrupt_out_writer`, writes each payload to bulk OUT.
//!
//! Recovery: any sub-future hitting a fatal transport error returns,
//! dropping its half of the channels. Peers observe the closes and
//! unwind. The `run` future resolves once all four are done; the
//! consumer's `RequestRx` returns `None`, signalling to the existing
//! session-level recovery to tear down and re-establish.

use crate::{Transport, TransportError, TransportErrorKind, TransportResult};
use alloc::{format, sync::Arc, vec, vec::Vec};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use futures_channel::{mpsc, oneshot};
use futures_util::{
    SinkExt, StreamExt,
    future::{BoxFuture, FutureExt},
    join,
};
use smoo_proto::{REQUEST_LEN, RESPONSE_LEN, Request, Response};

/// Capacity of the pump's internal channels. Sized large enough that the
/// gadget's full pipelining depth (queue_count × queue_depth, generally
/// O(16–32)) fits without backpressure stalls. Hardcoded for now — if a
/// future workload shows it's the wrong knob we can plumb it through.
const PUMP_CHANNEL_CAPACITY: usize = 64;

/// Receiver of decoded Requests. Closes when the pump's
/// `interrupt_in_reader` exits (transport error or peer shutdown).
pub type RequestRx = mpsc::Receiver<Request>;

/// Handle the consumer uses to push Responses (and optional bulk-OUT
/// payloads) and to reserve bulk-IN reads.
///
/// `Clone` for distribution to per-Request handler tasks. The
/// `queue_bulk_in_read` contract additionally requires that this method
/// be called from a single dispatcher loop in Request arrival order; do
/// not call it from handler tasks.
#[derive(Clone)]
pub struct HostPumpHandle {
    cmd_tx: mpsc::Sender<PumpCmd>,
    bulk_in_tx: mpsc::Sender<BulkInPending>,
}

/// Deferred bulk-IN read returned by [`HostPumpHandle::queue_bulk_in_read`].
/// Pass to a handler; await `await_payload()` to receive the bytes.
pub struct BulkInHandle {
    rx: oneshot::Receiver<TransportResult<Vec<u8>>>,
}

impl BulkInHandle {
    /// Await the bytes for this reservation. Resolves once the pump's
    /// `bulk_in_worker` has read them off the wire in FIFO order.
    pub async fn await_payload(self) -> TransportResult<Vec<u8>> {
        self.rx.await.unwrap_or_else(|_| Err(disconnected_err()))
    }
}

/// A future that drives the pump's four sub-futures to completion. The
/// caller spawns this on its executor (tokio for native, wasm-bindgen for
/// WASM). When it resolves, the pump has exited; the consumer's
/// `RequestRx` will already have returned `None`.
pub struct HostPumpTask {
    inner: BoxFuture<'static, ()>,
}

impl Future for HostPumpTask {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().inner.as_mut().poll(cx)
    }
}

/// Start the host I/O pump.
pub fn start_host_pump<T>(transport: T) -> (HostPumpHandle, RequestRx, HostPumpTask)
where
    T: Transport + Send + Sync + 'static,
{
    let transport = Arc::new(transport);
    let (cmd_tx, cmd_rx) = mpsc::channel::<PumpCmd>(PUMP_CHANNEL_CAPACITY);
    let (req_tx, req_rx) = mpsc::channel::<Request>(PUMP_CHANNEL_CAPACITY);
    let (bulk_in_tx, bulk_in_rx) = mpsc::channel::<BulkInPending>(PUMP_CHANNEL_CAPACITY);
    let (bulk_out_tx, bulk_out_rx) = mpsc::channel::<BulkOutPending>(PUMP_CHANNEL_CAPACITY);
    let task = HostPumpTask {
        inner: run_pump(
            transport,
            cmd_rx,
            req_tx,
            bulk_in_rx,
            bulk_out_tx,
            bulk_out_rx,
        )
        .boxed(),
    };
    (HostPumpHandle { cmd_tx, bulk_in_tx }, req_rx, task)
}

impl HostPumpHandle {
    /// Reserve a bulk-IN read of `byte_len` bytes in FIFO order.
    ///
    /// Bulk-IN payloads on the wire must arrive in the order their
    /// Requests hit interrupt IN. The pump's `bulk_in_worker` drains the
    /// reservation FIFO sequentially; **this method must be called from a
    /// single dispatcher loop in the same order Requests are emitted from
    /// [`RequestRx`]**, before any handler is spawned. The returned
    /// [`BulkInHandle`] is the handler's awaitable handle to the data.
    pub async fn queue_bulk_in_read(&self, byte_len: usize) -> TransportResult<BulkInHandle> {
        let (deliver, rx) = oneshot::channel();
        let mut tx = self.bulk_in_tx.clone();
        tx.send(BulkInPending { deliver, byte_len })
            .await
            .map_err(|_| disconnected_err())?;
        Ok(BulkInHandle { rx })
    }

    /// Send a Response with no bulk-OUT payload. Resolves when the
    /// Response is on the wire.
    pub async fn send_response(&self, response: Response) -> TransportResult<()> {
        self.send_response_with_bulk(response, None).await
    }

    /// Send a Response and an optional bulk-OUT payload. Resolves when
    /// the Response is on the wire and the bulk payload has been queued
    /// in FIFO order behind it. The bulk write itself completes
    /// concurrently in the pump's `bulk_out_worker`.
    pub async fn send_response_with_bulk(
        &self,
        response: Response,
        bulk_out: Option<Vec<u8>>,
    ) -> TransportResult<()> {
        let (reply, reply_rx) = oneshot::channel();
        let mut tx = self.cmd_tx.clone();
        tx.send(PumpCmd::SendResponseWithBulk {
            response,
            bulk_out,
            reply,
        })
        .await
        .map_err(|_| disconnected_err())?;
        reply_rx.await.unwrap_or_else(|_| Err(disconnected_err()))
    }
}

enum PumpCmd {
    SendResponseWithBulk {
        response: Response,
        bulk_out: Option<Vec<u8>>,
        reply: oneshot::Sender<TransportResult<()>>,
    },
}

struct BulkInPending {
    deliver: oneshot::Sender<TransportResult<Vec<u8>>>,
    byte_len: usize,
}

struct BulkOutPending {
    payload: Vec<u8>,
}

async fn run_pump<T>(
    transport: Arc<T>,
    cmd_rx: mpsc::Receiver<PumpCmd>,
    req_tx: mpsc::Sender<Request>,
    bulk_in_rx: mpsc::Receiver<BulkInPending>,
    bulk_out_tx: mpsc::Sender<BulkOutPending>,
    bulk_out_rx: mpsc::Receiver<BulkOutPending>,
) where
    T: Transport + Send + Sync + 'static,
{
    join!(
        run_interrupt_in_reader(transport.clone(), req_tx),
        run_interrupt_out_writer(transport.clone(), cmd_rx, bulk_out_tx),
        run_bulk_in_worker(transport.clone(), bulk_in_rx),
        run_bulk_out_worker(transport, bulk_out_rx),
    );
}

async fn run_interrupt_in_reader<T>(transport: Arc<T>, mut req_tx: mpsc::Sender<Request>)
where
    T: Transport + Send + Sync + 'static,
{
    loop {
        let mut buf = [0u8; REQUEST_LEN];
        match transport.read_interrupt(&mut buf).await {
            Ok(len) if len == REQUEST_LEN => {
                let request = match Request::decode(buf) {
                    Ok(r) => r,
                    Err(err) => {
                        tracing::warn!(?err, "interrupt IN: invalid Request");
                        continue;
                    }
                };
                if req_tx.send(request).await.is_err() {
                    break;
                }
            }
            Ok(len) => {
                tracing::warn!(
                    len,
                    expected = REQUEST_LEN,
                    "interrupt IN: partial Request read; dropping bytes"
                );
                continue;
            }
            Err(err) if err.kind() == TransportErrorKind::Timeout => continue,
            Err(err) => {
                tracing::warn!(?err, "interrupt IN read failed");
                break;
            }
        }
    }
}

async fn run_interrupt_out_writer<T>(
    transport: Arc<T>,
    mut cmd_rx: mpsc::Receiver<PumpCmd>,
    mut bulk_out_tx: mpsc::Sender<BulkOutPending>,
) where
    T: Transport + Send + Sync + 'static,
{
    while let Some(cmd) = cmd_rx.next().await {
        let PumpCmd::SendResponseWithBulk {
            response,
            bulk_out,
            reply,
        } = cmd;
        let encoded = response.encode();
        let interrupt_result: TransportResult<()> = match transport.write_interrupt(&encoded).await
        {
            Ok(written) if written == RESPONSE_LEN => Ok(()),
            Ok(written) => Err(TransportError::with_message(
                TransportErrorKind::Protocol,
                format!("response transfer truncated (expected {RESPONSE_LEN}, wrote {written})"),
            )),
            Err(err) => Err(err),
        };
        let final_result = match interrupt_result {
            Ok(()) => match bulk_out {
                Some(payload) => {
                    if bulk_out_tx.send(BulkOutPending { payload }).await.is_err() {
                        Err(disconnected_err())
                    } else {
                        Ok(())
                    }
                }
                None => Ok(()),
            },
            Err(err) => Err(err),
        };
        let was_err = final_result.is_err();
        let _ = reply.send(final_result);
        if was_err {
            break;
        }
    }
}

async fn run_bulk_in_worker<T>(transport: Arc<T>, mut rx: mpsc::Receiver<BulkInPending>)
where
    T: Transport + Send + Sync + 'static,
{
    while let Some(pending) = rx.next().await {
        let BulkInPending { deliver, byte_len } = pending;
        if byte_len > 16 * 1024 {
            tracing::debug!(bytes = byte_len, "bulk IN: starting large payload read");
        }
        let mut buf = vec![0u8; byte_len];
        let result = match transport.read_bulk(&mut buf).await {
            Ok(read) if read == byte_len => Ok(buf),
            Ok(read) => Err(TransportError::with_message(
                TransportErrorKind::Protocol,
                format!("bulk IN truncated (expected {byte_len}, got {read})"),
            )),
            Err(err) => Err(err),
        };
        let was_err = result.is_err();
        if !was_err && byte_len > 16 * 1024 {
            tracing::debug!(bytes = byte_len, "bulk IN: large payload read complete");
        }
        let _ = deliver.send(result);
        if was_err {
            break;
        }
    }
}

async fn run_bulk_out_worker<T>(transport: Arc<T>, mut rx: mpsc::Receiver<BulkOutPending>)
where
    T: Transport + Send + Sync + 'static,
{
    while let Some(pending) = rx.next().await {
        let BulkOutPending { payload } = pending;
        let len = payload.len();
        if len > 16 * 1024 {
            tracing::debug!(bytes = len, "bulk OUT: starting large payload write");
        }
        match transport.write_bulk(&payload).await {
            Ok(written) if written == len => {
                if len > 16 * 1024 {
                    tracing::debug!(bytes = len, "bulk OUT: large payload write complete");
                }
                continue;
            }
            Ok(written) => {
                tracing::warn!(
                    expected = len,
                    written,
                    "bulk OUT write truncated; tearing down"
                );
                break;
            }
            Err(err) => {
                tracing::warn!(?err, "bulk OUT write failed");
                break;
            }
        }
    }
}

fn disconnected_err() -> TransportError {
    TransportError::with_message(TransportErrorKind::Disconnected, "host pump disconnected")
}
