//! The IoPump

use crate::{SmooGadget, UblkQueueRuntime};
use anyhow::{Result, anyhow};
use smoo_proto::{OpCode, Request};
use std::sync::Arc;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tracing::trace;

/// Work item executed by the I/O pump.
pub struct IoWork {
    pub request: Request,
    pub req_len: usize,
    pub queue_id: u16,
    pub tag: u16,
    pub op: OpCode,
    pub queues: Arc<UblkQueueRuntime>,
}

struct IoCommand {
    work: IoWork,
    completion: oneshot::Sender<Result<()>>,
}

/// Single-owner handle to the background I/O pump.
pub struct IoPumpHandle {
    tx: mpsc::Sender<IoCommand>,
    join: JoinHandle<()>,
}

impl IoPumpHandle {
    /// Spawn a pump bound to the provided gadget and channel capacity.
    pub fn spawn(gadget: Arc<SmooGadget>, capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel(capacity);
        let join = tokio::spawn(run_pump(gadget, rx));
        Self { tx, join }
    }

    /// Submit a work item and await its completion.
    pub async fn submit(&self, work: IoWork) -> Result<()> {
        let (completion, rx) = oneshot::channel();
        self.tx
            .send(IoCommand { work, completion })
            .await
            .map_err(|_| anyhow!("io pump stopped"))?;
        rx.await.map_err(|_| anyhow!("io pump dropped result"))?
    }

    /// Stop the pump and wait for it to exit.
    pub async fn shutdown(self) {
        let IoPumpHandle { tx, join } = self;
        drop(tx);
        join.abort();
        let _ = join.await;
    }
}

async fn run_pump(gadget: Arc<SmooGadget>, mut rx: mpsc::Receiver<IoCommand>) {
    while let Some(IoCommand { work, completion }) = rx.recv().await {
        let result = process_work(&gadget, work).await;
        if completion.send(result).is_err() {
            trace!("io pump: completion receiver dropped");
        }
    }
    trace!("io pump: channel closed; exiting");
}

async fn process_work(gadget: &SmooGadget, work: IoWork) -> Result<()> {
    trace!(
        export_id = work.request.export_id,
        request_id = work.request.request_id,
        queue = work.queue_id,
        tag = work.tag,
        op = ?work.op,
        bytes = work.req_len,
        "io pump: dispatch request"
    );
    gadget
        .send_request(work.request)
        .await
        .map_err(|err| anyhow!("send smoo request: {err:#}"))?;

    if work.req_len == 0 {
        return Ok(());
    }

    match work.op {
        OpCode::Read => {
            let mut buffer = work
                .queues
                .checkout_buffer(work.queue_id, work.tag)
                .map_err(|err| anyhow!("checkout buffer for read: {err:#}"))?;
            gadget
                .read_bulk_buffer(&mut buffer.as_mut_slice()[..work.req_len])
                .await
                .map_err(|err| anyhow!("bulk read payload: {err:#}"))?;
        }
        OpCode::Write => {
            let mut buffer = work
                .queues
                .checkout_buffer(work.queue_id, work.tag)
                .map_err(|err| anyhow!("checkout buffer for write: {err:#}"))?;
            gadget
                .write_bulk_buffer(&mut buffer.as_mut_slice()[..work.req_len])
                .await
                .map_err(|err| anyhow!("bulk write payload: {err:#}"))?;
        }
        _ => {}
    }

    Ok(())
}
