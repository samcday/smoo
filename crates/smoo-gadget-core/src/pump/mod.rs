//! Pipelined gadget-side I/O pump.
//!
//! Four worker tasks cooperate over an [`InFlightRegistry`] keyed on
//! `(export_id, request_id)` and per-direction bulk FIFOs. The bulk FIFOs
//! enforce HACKING.md §4's "bulk order = interrupt order on the same
//! direction" wire invariant: each FIFO is populated by the task that owns
//! the interrupt write that anchors the bulk transfer, and drained in
//! order by a dedicated bulk worker. Responses on interrupt OUT may arrive
//! out-of-order; the registry demuxes them by request_id.
//!
//! Tasks:
//! - `interrupt_in_writer` drains the submit channel; inserts entries into
//!   the registry, writes Requests to interrupt IN, and for Write ops
//!   enqueues the bulk-IN follow-up so the gadget's bulk IN data is sent
//!   in Request order.
//! - `interrupt_out_reader` reads Responses; demuxes via the registry. For
//!   non-Read ops (or zero-length Reads) completes inline; for Reads with
//!   payload it enqueues the bulk-OUT follow-up.
//! - `bulk_in_worker` drains the bulk-IN FIFO; checks out the matching
//!   ublk buffer and sends its contents on bulk IN.
//! - `bulk_out_worker` drains the bulk-OUT FIFO; checks out the buffer and
//!   reads from bulk OUT into it. Issues `complete_io` to ublk and signals
//!   the submit caller's completion oneshot.
//!
//! Backpressure: a `Semaphore` sized to `capacity` (queue_count *
//! queue_depth) gates submit. The owned permit travels with the entry
//! through the pipeline and is released when the entry is removed from
//! the registry, so at most `capacity` requests are ever in flight.
//!
//! Recovery: any worker observing a fatal error transitions the shared
//! [`PumpStateHandle`] to `Faulted`. Peer tasks observe via
//! `watch::Receiver` and exit. After all four tasks join, the supervisor
//! drains the registry; remaining entries' completion oneshots are
//! dropped, surfacing an error to the submit caller, which the existing
//! `drain_outstanding_bounded` machinery in `smoo-gadget-app` re-parks for
//! replay.

mod registry;
mod state;

use crate::{SmooGadget, UblkIoRequest, UblkQueueRuntime};
use anyhow::{Result, anyhow};
use registry::{InFlightKey, InFlightRegistry};
use smoo_proto::{OpCode, Request, Response};
use state::{PumpState, PumpStateHandle};
use std::sync::Arc;
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch},
    task::{JoinHandle, JoinSet},
};
use tracing::{debug, trace, warn};

#[cfg(feature = "metrics")]
fn observe_inflight(registry: &InFlightRegistry<InFlightEntry>) {
    crate::metrics::record_inflight_requests(registry.len());
}

#[cfg(not(feature = "metrics"))]
fn observe_inflight(_registry: &InFlightRegistry<InFlightEntry>) {}

/// Work item executed by the I/O pump.
pub struct IoWork {
    pub ublk_request: UblkIoRequest,
    pub request: Request,
    pub req_len: usize,
    pub block_size: usize,
    pub queue_id: u16,
    pub tag: u16,
    pub op: OpCode,
    pub queues: Arc<UblkQueueRuntime>,
}

/// Single-owner handle to the background I/O pump.
pub struct IoPumpHandle {
    submit: mpsc::Sender<SubmitMsg>,
    permits: Arc<Semaphore>,
}

impl Clone for IoPumpHandle {
    fn clone(&self) -> Self {
        Self {
            submit: self.submit.clone(),
            permits: self.permits.clone(),
        }
    }
}

impl IoPumpHandle {
    /// Spawn a pump bound to the provided gadget.
    ///
    /// `capacity` is the maximum number of concurrent in-flight requests
    /// across all exports — typically `queue_count * queue_depth`.
    pub fn spawn(gadget: Arc<SmooGadget>, capacity: usize) -> (Self, JoinHandle<()>) {
        let capacity = capacity.max(1);
        let permits = Arc::new(Semaphore::new(capacity));
        let (submit_tx, submit_rx) = mpsc::channel(capacity);
        let handle = Self {
            submit: submit_tx,
            permits: permits.clone(),
        };
        let task = tokio::spawn(supervise(gadget, submit_rx, capacity));
        (handle, task)
    }

    /// Submit a work item and await its completion.
    ///
    /// Resolves to `Ok(())` once the I/O has been signalled to ublk via
    /// `complete_io`. Resolves to `Err` if the pump faulted, the response
    /// did not match the expected `(export_id, request_id)` shape, or the
    /// ublk completion call itself failed. Callers re-park the work for
    /// replay (the request_id encoding is deterministic, so a replayed
    /// request reuses its key).
    pub async fn submit(&self, work: IoWork) -> Result<()> {
        let permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow!("io pump stopped"))?;
        let (completion, completion_rx) = oneshot::channel();
        self.submit
            .send(SubmitMsg {
                work,
                completion,
                permit,
            })
            .await
            .map_err(|_| anyhow!("io pump stopped"))?;
        completion_rx
            .await
            .map_err(|_| anyhow!("io pump dropped result"))?
    }
}

struct SubmitMsg {
    work: IoWork,
    completion: oneshot::Sender<Result<()>>,
    permit: OwnedSemaphorePermit,
}

/// Registry value: everything needed to complete an in-flight I/O once its
/// Response (and optional bulk-OUT payload for Reads) has been processed.
struct InFlightEntry {
    work: IoWork,
    completion: oneshot::Sender<Result<()>>,
    /// Held for the entry's lifetime; dropped when the entry leaves the
    /// pipeline, releasing capacity for the next submit.
    _permit: OwnedSemaphorePermit,
}

/// Pending bulk-IN write enqueued after the corresponding Write Request
/// hits the wire on interrupt IN. Drained in FIFO order by `bulk_in_worker`.
struct BulkInPending {
    queues: Arc<UblkQueueRuntime>,
    queue_id: u16,
    tag: u16,
    req_len: usize,
}

/// Pending bulk-OUT read enqueued after the corresponding Read Response is
/// observed on interrupt OUT. Drained in FIFO order by `bulk_out_worker`.
struct BulkOutPending {
    entry: InFlightEntry,
    read_len: usize,
}

async fn supervise(
    gadget: Arc<SmooGadget>,
    submit_rx: mpsc::Receiver<SubmitMsg>,
    capacity: usize,
) {
    let registry = Arc::new(InFlightRegistry::<InFlightEntry>::new());
    let (state_handle, state_rx) = PumpStateHandle::new();
    let (bulk_in_tx, bulk_in_rx) = mpsc::channel::<BulkInPending>(capacity);
    let (bulk_out_tx, bulk_out_rx) = mpsc::channel::<BulkOutPending>(capacity);

    let mut workers = JoinSet::new();
    workers.spawn(interrupt_in_writer(
        gadget.clone(),
        submit_rx,
        bulk_in_tx,
        registry.clone(),
        state_handle.clone(),
        state_rx.clone(),
    ));
    workers.spawn(interrupt_out_reader(
        gadget.clone(),
        bulk_out_tx,
        registry.clone(),
        state_handle.clone(),
        state_rx.clone(),
    ));
    workers.spawn(bulk_in_worker(
        gadget.clone(),
        bulk_in_rx,
        state_handle.clone(),
        state_rx.clone(),
    ));
    workers.spawn(bulk_out_worker(
        gadget,
        bulk_out_rx,
        state_handle.clone(),
        state_rx,
    ));

    while let Some(joined) = workers.join_next().await {
        if let Err(err) = joined {
            warn!(?err, "io pump worker panicked");
            state_handle.fault();
        }
    }

    // All workers have exited. Drain any entries still in the registry.
    // Each entry's completion oneshot is dropped here, surfacing an error
    // to the submit caller so it can re-park for replay.
    let leftover = registry.close();
    if !leftover.is_empty() {
        debug!(
            count = leftover.len(),
            "draining outstanding requests after pump exit",
        );
    }
    drop(leftover);
}

async fn interrupt_in_writer(
    gadget: Arc<SmooGadget>,
    mut submit_rx: mpsc::Receiver<SubmitMsg>,
    bulk_in_tx: mpsc::Sender<BulkInPending>,
    registry: Arc<InFlightRegistry<InFlightEntry>>,
    state: PumpStateHandle,
    mut state_rx: watch::Receiver<PumpState>,
) {
    loop {
        if state_rx.borrow().is_terminal() {
            break;
        }
        let msg = tokio::select! {
            biased;
            _ = state_rx.changed() => continue,
            msg = submit_rx.recv() => match msg {
                Some(m) => m,
                None => break,
            },
        };

        let SubmitMsg {
            work,
            completion,
            permit,
        } = msg;
        let request = work.request;
        let key: InFlightKey = (request.export_id, request.request_id);
        let queue_id = work.queue_id;
        let tag = work.tag;
        let op = work.op;
        let req_len = work.req_len;
        let queues = work.queues.clone();
        let entry = InFlightEntry {
            work,
            completion,
            _permit: permit,
        };

        // Insert before the wire write so the response handler can find us
        // even if the host responds before this task gets back to its loop.
        if let Err(err) = registry.insert(key, entry) {
            warn!(?err, "registry rejected submit; pump must be terminal");
            // Entry dropped — completion oneshot drop signals submit caller.
            continue;
        }
        observe_inflight(&registry);

        trace!(
            export_id = request.export_id,
            request_id = request.request_id,
            ?op,
            req_len,
            "interrupt IN: writing Request"
        );
        if let Err(err) = gadget.send_request(request).await {
            warn!(?err, "interrupt IN write failed");
            if let Some(entry) = registry.take(key) {
                let _ = entry.completion.send(Err(err.context("send Request")));
            }
            state.fault();
            break;
        }

        if op == OpCode::Write && req_len > 0 {
            let pending = BulkInPending {
                queues,
                queue_id,
                tag,
                req_len,
            };
            if bulk_in_tx.send(pending).await.is_err() {
                // bulk_in_worker exited first; nothing to do but shut down.
                state.fault();
                break;
            }
        }
    }

    state.shutdown();
}

async fn interrupt_out_reader(
    gadget: Arc<SmooGadget>,
    bulk_out_tx: mpsc::Sender<BulkOutPending>,
    registry: Arc<InFlightRegistry<InFlightEntry>>,
    state: PumpStateHandle,
    mut state_rx: watch::Receiver<PumpState>,
) {
    loop {
        if state_rx.borrow().is_terminal() {
            break;
        }
        let response = tokio::select! {
            biased;
            _ = state_rx.changed() => continue,
            res = gadget.read_response() => match res {
                Ok(r) => r,
                Err(err) => {
                    warn!(?err, "interrupt OUT read failed");
                    state.fault();
                    break;
                }
            },
        };
        if let Err(err) = handle_response(&bulk_out_tx, &registry, response).await {
            warn!(?err, "response handling failed");
            state.fault();
            break;
        }
    }
    state.shutdown();
}

async fn handle_response(
    bulk_out_tx: &mpsc::Sender<BulkOutPending>,
    registry: &InFlightRegistry<InFlightEntry>,
    response: Response,
) -> Result<()> {
    let key: InFlightKey = (response.export_id, response.request_id);
    let Some(entry) = registry.take(key) else {
        debug!(
            export_id = response.export_id,
            request_id = response.request_id,
            "response with no pending entry — discarding"
        );
        return Ok(());
    };
    observe_inflight(registry);

    if response.op != entry.work.op {
        let msg = format!(
            "response opcode mismatch for ({}, {}): expected {:?}, got {:?}",
            response.export_id, response.request_id, entry.work.op, response.op,
        );
        let _ = entry.completion.send(Err(anyhow!("{msg}")));
        return Err(anyhow!(msg));
    }

    let status = compute_status(&response, entry.work.req_len, entry.work.block_size);

    if response.op == OpCode::Read && status > 0 && entry.work.req_len > 0 {
        let read_len = (status as usize).min(entry.work.req_len);
        let pending = BulkOutPending { entry, read_len };
        bulk_out_tx
            .send(pending)
            .await
            .map_err(|_| anyhow!("bulk OUT worker shutting down"))?;
        return Ok(());
    }

    complete_entry(entry, status);
    Ok(())
}

async fn bulk_in_worker(
    gadget: Arc<SmooGadget>,
    mut rx: mpsc::Receiver<BulkInPending>,
    state: PumpStateHandle,
    mut state_rx: watch::Receiver<PumpState>,
) {
    loop {
        if state_rx.borrow().is_terminal() {
            break;
        }
        let pending = tokio::select! {
            biased;
            _ = state_rx.changed() => continue,
            msg = rx.recv() => match msg {
                Some(p) => p,
                None => break,
            },
        };
        let BulkInPending {
            queues,
            queue_id,
            tag,
            req_len,
        } = pending;
        let mut buffer = match queues.checkout_buffer(queue_id, tag) {
            Ok(b) => b,
            Err(err) => {
                warn!(queue_id, tag, ?err, "checkout buffer for bulk IN");
                state.fault();
                break;
            }
        };
        if let Err(err) = gadget
            .write_bulk_buffer(&mut buffer.as_mut_slice()[..req_len])
            .await
        {
            warn!(queue_id, tag, ?err, "bulk IN write failed");
            state.fault();
            break;
        }
    }
    state.shutdown();
}

async fn bulk_out_worker(
    gadget: Arc<SmooGadget>,
    mut rx: mpsc::Receiver<BulkOutPending>,
    state: PumpStateHandle,
    mut state_rx: watch::Receiver<PumpState>,
) {
    loop {
        if state_rx.borrow().is_terminal() {
            break;
        }
        let pending = tokio::select! {
            biased;
            _ = state_rx.changed() => continue,
            msg = rx.recv() => match msg {
                Some(p) => p,
                None => break,
            },
        };
        let BulkOutPending { entry, read_len } = pending;
        let queue_id = entry.work.queue_id;
        let tag = entry.work.tag;
        let xfer_result = {
            let mut buffer = match entry.work.queues.checkout_buffer(queue_id, tag) {
                Ok(b) => b,
                Err(err) => {
                    let _ = entry
                        .completion
                        .send(Err(err.context("checkout buffer for bulk OUT")));
                    state.fault();
                    break;
                }
            };
            gadget
                .read_bulk_buffer(&mut buffer.as_mut_slice()[..read_len])
                .await
        };
        if let Err(err) = xfer_result {
            let _ = entry.completion.send(Err(err.context("bulk OUT read failed")));
            state.fault();
            break;
        }
        let status = i32::try_from(read_len).unwrap_or(i32::MAX);
        complete_entry(entry, status);
    }
    state.shutdown();
}

fn compute_status(response: &Response, req_len: usize, block_size: usize) -> i32 {
    if response.status == 0 {
        if matches!(response.op, OpCode::Read | OpCode::Write) {
            let reported = (response.num_blocks as usize).saturating_mul(block_size);
            i32::try_from(reported.min(req_len)).unwrap_or(i32::MAX)
        } else {
            0
        }
    } else {
        -i32::from(response.status)
    }
}

fn complete_entry(entry: InFlightEntry, status: i32) {
    let InFlightEntry {
        work, completion, ..
    } = entry;
    let request = work.request;
    let result = work
        .queues
        .complete_io(work.ublk_request, status)
        .map_err(|err| anyhow!("complete ublk io failed: {err:#}"));
    if status < 0 {
        warn!(
            export_id = request.export_id,
            request_id = request.request_id,
            status,
            "io pump: request completed with error",
        );
    } else {
        trace!(
            export_id = request.export_id,
            request_id = request.request_id,
            status,
            "io pump: request completed",
        );
    }
    let _ = completion.send(result);
}
