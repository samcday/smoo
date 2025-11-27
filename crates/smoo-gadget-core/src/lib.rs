use anyhow::{Context, Result, anyhow, ensure};
use dma_heap::HeapKind;
use smoo_proto::{
    CONFIG_EXPORTS_REQ_TYPE, CONFIG_EXPORTS_REQUEST, IDENT_LEN, IDENT_REQUEST, Ident, RESPONSE_LEN,
    Request, Response, SMOO_STATUS_FLAG_EXPORT_ACTIVE, SMOO_STATUS_LEN, SMOO_STATUS_REQ_TYPE,
    SMOO_STATUS_REQUEST, SmooStatusV0,
};
use std::{
    cmp,
    fs::File as StdFile,
    io,
    os::fd::{AsRawFd, OwnedFd, RawFd},
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    task,
};
use tracing::trace;

mod dma;
mod link;
mod runtime;
mod state_store;

use crate::dma::{BufferHandle, BufferPool, dmabuf_transfer_blocking};
pub use link::{LinkCommand, LinkController, LinkState};
pub use runtime::{
    ExportController, ExportReconcileContext, ExportState, GadgetRuntime, IoStateKind,
    RuntimeTunables,
};
pub use smoo_gadget_ublk::{SmooUblk, SmooUblkDevice, UblkBuffer, UblkIoRequest, UblkOp};
pub use smoo_proto::{ConfigExport, ConfigExportsV0};
pub use state_store::{ExportFlags, ExportSpec, PersistedExportRecord, StateStore};

const USB_DIR_IN: u8 = 0x80;
const USB_TYPE_VENDOR: u8 = 0x40;
const USB_RECIP_INTERFACE: u8 = 0x01;
const SMOO_REQ_TYPE: u8 = USB_DIR_IN | USB_TYPE_VENDOR | USB_RECIP_INTERFACE;

const SETUP_STAGE_LEN: usize = 8;
const FUNCTIONFS_EVENT_SIZE: usize = SETUP_STAGE_LEN + 4;

/// File descriptor bundle for a FunctionFS interface (data-plane endpoints only).
pub struct FunctionfsEndpoints {
    pub interrupt_in: OwnedFd,
    pub interrupt_out: OwnedFd,
    pub bulk_in: OwnedFd,
    pub bulk_out: OwnedFd,
}

impl FunctionfsEndpoints {
    pub fn new(
        interrupt_in: OwnedFd,
        interrupt_out: OwnedFd,
        bulk_in: OwnedFd,
        bulk_out: OwnedFd,
    ) -> Self {
        Self {
            interrupt_in,
            interrupt_out,
            bulk_in,
            bulk_out,
        }
    }
}

/// Async wrapper around the FunctionFS control endpoint (ep0).
///
/// This controller exposes raw FunctionFS events so higher-level code can react to
/// lifecycle changes (BIND/ENABLE/DISABLE/etc.) and vendor-specific SETUP packets.
/// Future configuration handlers (e.g. CONFIG_EXPORTS) can listen for [`Ep0Event::Setup`]
/// and interact with the host using the [`write_in`], [`read_out`], and [`stall`]
/// helpers.
pub struct Ep0Controller {
    ep0: File,
}

impl Ep0Controller {
    /// Construct a controller from a FunctionFS ep0 file descriptor.
    pub fn from_owned_fd(fd: OwnedFd) -> io::Result<Self> {
        let file = to_tokio_file(fd)?;
        Ok(Self::new(file))
    }

    fn new(ep0: File) -> Self {
        Self { ep0 }
    }

    /// Read the next FunctionFS event from ep0.
    pub async fn next_event(&mut self) -> Result<Ep0Event> {
        let mut buf = [0u8; FUNCTIONFS_EVENT_SIZE];
        self.ep0
            .read_exact(&mut buf)
            .await
            .context("read ep0 event")?;
        Ep0Event::from_bytes(buf)
    }

    /// Send an IN data stage (device → host) for the current control transfer.
    pub async fn write_in(&mut self, data: &[u8]) -> Result<()> {
        self.ep0.write_all(data).await.context("write ep0 data")?;
        self.ep0.flush().await.context("flush ep0")?;
        Ok(())
    }

    /// Read an OUT data stage (host → device) for the current control transfer.
    pub async fn read_out(&mut self, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        self.ep0.read_exact(buf).await.context("read ep0 payload")?;
        Ok(())
    }

    /// Stall the current control transfer.
    pub async fn stall(&mut self) -> Result<()> {
        // Writing a single zero byte signals a halt condition to FunctionFS.
        self.ep0
            .write_all(&[0u8])
            .await
            .context("stall ep0 control")?;
        self.ep0.flush().await.context("flush ep0 after stall")?;
        Ok(())
    }
}

/// FunctionFS control-plane events surfaced by [`Ep0Controller`].
#[derive(Clone, Copy, Debug)]
pub enum Ep0Event {
    Bind,
    Unbind,
    Enable,
    Disable,
    Suspend,
    Resume,
    Setup(SetupPacket),
}

impl Ep0Event {
    fn from_bytes(bytes: [u8; FUNCTIONFS_EVENT_SIZE]) -> Result<Self> {
        let event_type = Ep0EventType::try_from(bytes[SETUP_STAGE_LEN])?;
        Ok(match event_type {
            Ep0EventType::Bind => Ep0Event::Bind,
            Ep0EventType::Unbind => Ep0Event::Unbind,
            Ep0EventType::Enable => Ep0Event::Enable,
            Ep0EventType::Disable => Ep0Event::Disable,
            Ep0EventType::Suspend => Ep0Event::Suspend,
            Ep0EventType::Resume => Ep0Event::Resume,
            Ep0EventType::Setup => {
                let mut setup_bytes = [0u8; SETUP_STAGE_LEN];
                setup_bytes.copy_from_slice(&bytes[..SETUP_STAGE_LEN]);
                Ep0Event::Setup(SetupPacket::from_bytes(setup_bytes))
            }
        })
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
enum Ep0EventType {
    Bind = 0,
    Unbind = 1,
    Enable = 2,
    Disable = 3,
    Setup = 4,
    Suspend = 5,
    Resume = 6,
}

impl TryFrom<u8> for Ep0EventType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Ep0EventType::Bind),
            1 => Ok(Ep0EventType::Unbind),
            2 => Ok(Ep0EventType::Enable),
            3 => Ok(Ep0EventType::Disable),
            4 => Ok(Ep0EventType::Setup),
            5 => Ok(Ep0EventType::Suspend),
            6 => Ok(Ep0EventType::Resume),
            other => Err(anyhow!("unknown FunctionFS event type {other}")),
        }
    }
}

/// Decoded USB control request observed on ep0.
#[derive(Clone, Copy, Debug)]
pub struct SetupPacket {
    request_type: u8,
    request: u8,
    value: u16,
    index: u16,
    length: u16,
}

impl SetupPacket {
    /// Construct a SetupPacket from raw USB control fields.
    pub fn from_fields(request_type: u8, request: u8, value: u16, index: u16, length: u16) -> Self {
        let bytes = [
            request_type,
            request,
            value.to_le_bytes()[0],
            value.to_le_bytes()[1],
            index.to_le_bytes()[0],
            index.to_le_bytes()[1],
            length.to_le_bytes()[0],
            length.to_le_bytes()[1],
        ];
        Self::from_bytes(bytes)
    }

    fn from_bytes(bytes: [u8; SETUP_STAGE_LEN]) -> Self {
        Self {
            request_type: bytes[0],
            request: bytes[1],
            value: u16::from_le_bytes([bytes[2], bytes[3]]),
            index: u16::from_le_bytes([bytes[4], bytes[5]]),
            length: u16::from_le_bytes([bytes[6], bytes[7]]),
        }
    }

    /// bmRequestType
    pub fn request_type(&self) -> u8 {
        self.request_type
    }

    /// bRequest
    pub fn request(&self) -> u8 {
        self.request
    }

    /// wValue
    pub fn value(&self) -> u16 {
        self.value
    }

    /// wIndex
    pub fn index(&self) -> u16 {
        self.index
    }

    /// wLength
    pub fn length(&self) -> u16 {
        self.length
    }

    fn direction(&self) -> ControlDirection {
        if self.request_type & USB_DIR_IN != 0 {
            ControlDirection::In
        } else {
            ControlDirection::Out
        }
    }
}

/// Gadget configuration parameters that stay constant while the device is active.
#[derive(Clone, Copy)]
pub struct GadgetConfig {
    pub ident: Ident,
    pub queue_count: u16,
    pub queue_depth: u16,
    pub max_io_bytes: usize,
    pub dma_heap: Option<DmaHeap>,
}

impl GadgetConfig {
    pub fn new(
        ident: Ident,
        queue_count: u16,
        queue_depth: u16,
        max_io_bytes: usize,
        dma_heap: Option<DmaHeap>,
    ) -> Self {
        Self {
            ident,
            queue_count,
            queue_depth,
            max_io_bytes,
            dma_heap,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum DmaHeap {
    System,
    Cma,
    Reserved,
}

impl DmaHeap {
    fn to_heap_kind(self) -> HeapKind {
        match self {
            DmaHeap::System => HeapKind::System,
            DmaHeap::Cma => HeapKind::Cma,
            DmaHeap::Reserved => {
                HeapKind::Custom(std::path::PathBuf::from("/dev/dma_heap/reserved"))
            }
        }
    }
}

/// High-level FunctionFS gadget driver.
pub struct SmooGadget {
    data_plane: GadgetDataPlane,
    ident: Ident,
}

#[async_trait::async_trait]
pub trait ControlIo {
    async fn write_in(&mut self, data: &[u8]) -> Result<()>;
    async fn read_out(&mut self, buf: &mut [u8]) -> Result<()>;
    async fn stall(&mut self) -> Result<()>;
}

#[async_trait::async_trait]
impl ControlIo for Ep0Controller {
    async fn write_in(&mut self, data: &[u8]) -> Result<()> {
        Ep0Controller::write_in(self, data).await
    }

    async fn read_out(&mut self, buf: &mut [u8]) -> Result<()> {
        Ep0Controller::read_out(self, buf).await
    }

    async fn stall(&mut self) -> Result<()> {
        Ep0Controller::stall(self).await
    }
}

impl SmooGadget {
    pub fn new(endpoints: FunctionfsEndpoints, config: GadgetConfig) -> Result<Self> {
        let FunctionfsEndpoints {
            interrupt_in,
            interrupt_out,
            bulk_in,
            bulk_out,
        } = endpoints;
        Ok(Self {
            data_plane: GadgetDataPlane::new(
                interrupt_in,
                interrupt_out,
                bulk_in,
                bulk_out,
                config.queue_count,
                config.queue_depth,
                config.max_io_bytes,
                config.dma_heap,
            )?,
            ident: config.ident,
        })
    }

    /// Send a Request message to the host over the interrupt IN endpoint.
    pub async fn send_request(&mut self, request: Request) -> Result<()> {
        self.data_plane.send_request(request).await
    }

    /// Receive a Response message from the host over the interrupt OUT endpoint.
    pub async fn read_response(&mut self) -> Result<Response> {
        self.data_plane.read_response().await
    }

    /// Read a bulk payload from the host (bulk OUT → gadget).
    pub async fn read_bulk(&mut self, buf: &mut [u8]) -> Result<()> {
        self.data_plane.read_bulk(buf).await
    }

    /// Write a bulk payload to the host (bulk IN → host).
    pub async fn write_bulk(&mut self, buf: &[u8]) -> Result<()> {
        self.data_plane.write_bulk(buf).await
    }

    /// Read a bulk payload directly into a buffer, using DMA-BUF when available.
    pub async fn read_bulk_buffer(&mut self, buf: &mut [u8]) -> Result<()> {
        self.data_plane.read_bulk_buffer(buf).await
    }

    /// Write a bulk payload from a buffer, using DMA-BUF when available.
    pub async fn write_bulk_buffer(&mut self, buf: &mut [u8]) -> Result<()> {
        self.data_plane.write_bulk_buffer(buf).await
    }

    /// Access the data-plane controller directly.
    pub fn data_plane_mut(&mut self) -> &mut GadgetDataPlane {
        &mut self.data_plane
    }

    /// Current IDENT response advertised by the gadget.
    pub fn ident(&self) -> Ident {
        self.ident
    }

    /// Create a control-plane helper for parsing vendor SETUP packets.
    pub fn control_handler(&self) -> GadgetControl {
        GadgetControl::new(self.ident)
    }
}

/// Snapshot of dynamic gadget status advertised via SMOO_STATUS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GadgetStatusReport {
    pub session_id: u64,
    pub export_count: u32,
}

impl GadgetStatusReport {
    pub fn new(session_id: u64, export_count: u32) -> Self {
        Self {
            session_id,
            export_count,
        }
    }

    pub fn export_active(&self) -> bool {
        self.export_count > 0
    }
}

/// Control-plane helper that parses vendor SETUP packets and emits high-level commands.
#[derive(Clone, Copy, Debug)]
pub struct GadgetControl {
    ident: Ident,
}

impl GadgetControl {
    fn new(ident: Ident) -> Self {
        Self { ident }
    }

    /// Handle a vendor-specific SETUP packet.
    ///
    /// Returns [`SetupCommand`] when additional action is required (e.g. CONFIG_EXPORTS).
    /// All control responses/ACKs are written through `io` internally.
    pub async fn handle_setup_packet(
        &self,
        io: &mut (impl ControlIo + Send),
        setup: SetupPacket,
        status: &GadgetStatusReport,
    ) -> Result<Option<SetupCommand>> {
        if setup.request() == IDENT_REQUEST && setup.request_type() == SMOO_REQ_TYPE {
            ensure!(
                setup.direction() == ControlDirection::In,
                "GET_IDENT must be an IN transfer"
            );
            ensure!(
                setup.length() as usize >= IDENT_LEN,
                "GET_IDENT length too small"
            );
            trace!("ep0: GET_IDENT");
            let ident = self.ident.encode();
            let len = cmp::min(setup.length() as usize, ident.len());
            io.write_in(&ident[..len])
                .await
                .context("reply to GET_IDENT")?;
            return Ok(None);
        }

        if setup.request() == SMOO_STATUS_REQUEST && setup.request_type() == SMOO_STATUS_REQ_TYPE {
            ensure!(
                setup.direction() == ControlDirection::In,
                "SMOO_STATUS must be an IN transfer"
            );
            ensure!(
                setup.length() as usize >= SMOO_STATUS_LEN,
                "SMOO_STATUS buffer too small"
            );
            trace!(
                current_exports = status.export_count,
                session_id = status.session_id,
                "ep0: SMOO_STATUS"
            );
            let mut flags = 0;
            if status.export_active() {
                flags |= SMOO_STATUS_FLAG_EXPORT_ACTIVE;
            }
            let payload = SmooStatusV0::new(flags, status.export_count, status.session_id);
            let encoded = payload.encode();
            let len = cmp::min(encoded.len(), setup.length() as usize);
            io.write_in(&encoded[..len])
                .await
                .context("write SMOO_STATUS response")?;
            return Ok(None);
        }

        if setup.request() == CONFIG_EXPORTS_REQUEST
            && setup.request_type() == CONFIG_EXPORTS_REQ_TYPE
        {
            let len = setup.length() as usize;
            ensure!(
                len >= ConfigExportsV0::HEADER_LEN,
                "CONFIG_EXPORTS payload too short"
            );
            trace!(len, "ep0: CONFIG_EXPORTS setup");
            let mut buf = vec![0u8; len];
            io.read_out(&mut buf).await.context("read CONFIG_EXPORTS")?;
            let payload = ConfigExportsV0::try_from_slice(&buf)
                .map_err(|err| anyhow!("parse CONFIG_EXPORTS payload: {err}"))?;
            return Ok(Some(SetupCommand::Config(payload)));
        }

        io.stall()
            .await
            .context("stall unsupported control request")?;
        Err(anyhow!(
            "unsupported setup request {:#x} type {:#x}",
            setup.request(),
            setup.request_type()
        ))
    }
}

/// Commands emitted by [`GadgetControl`] for the runtime to apply.
#[derive(Clone, Debug)]
pub enum SetupCommand {
    Config(ConfigExportsV0),
}

/// Data-plane controller that owns the FunctionFS interrupt and bulk endpoints.
///
/// Today it still drives a single export, but the separation from [`Ep0Controller`]
/// allows future work to multiplex multiple exports or schedule heavy work without
/// blocking EP0.
pub struct GadgetDataPlane {
    interrupt_in: File,
    interrupt_out: File,
    bulk_in: File,
    bulk_out: File,
    buffers: Option<BufferPool>,
}

impl GadgetDataPlane {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        interrupt_in: OwnedFd,
        interrupt_out: OwnedFd,
        bulk_in: OwnedFd,
        bulk_out: OwnedFd,
        queue_count: u16,
        queue_depth: u16,
        max_io_bytes: usize,
        dma_heap: Option<DmaHeap>,
    ) -> Result<Self> {
        let buffers = if let Some(heap) = dma_heap {
            let prealloc = queue_count as usize * queue_depth as usize;
            let cap = prealloc;
            Some(
                BufferPool::new(
                    bulk_in.as_raw_fd(),
                    bulk_out.as_raw_fd(),
                    Some(heap.to_heap_kind()),
                    max_io_bytes,
                    prealloc,
                    cap,
                )
                .context("init DMA buffer pool")?,
            )
        } else {
            None
        };
        Ok(Self {
            interrupt_in: to_tokio_file(interrupt_in)?,
            interrupt_out: to_tokio_file(interrupt_out)?,
            bulk_in: to_tokio_file(bulk_in)?,
            bulk_out: to_tokio_file(bulk_out)?,
            buffers,
        })
    }

    pub async fn send_request(&mut self, request: Request) -> Result<()> {
        let encoded = request.encode();
        trace!(bytes = encoded.len(), "interrupt IN: sending Request");
        self.interrupt_in
            .write_all(&encoded)
            .await
            .context("write request to interrupt IN")?;
        self.interrupt_in
            .flush()
            .await
            .context("flush interrupt IN")?;
        trace!("interrupt IN: Request flushed");
        Ok(())
    }

    pub async fn read_response(&mut self) -> Result<Response> {
        let mut buf = [0u8; RESPONSE_LEN];
        trace!(bytes = buf.len(), "interrupt OUT: reading Response");
        self.interrupt_out
            .read_exact(&mut buf)
            .await
            .context("read response from interrupt OUT")?;
        trace!("interrupt OUT: Response received");
        Response::try_from(buf.as_slice()).map_err(|err| anyhow!("decode response: {err}"))
    }

    pub async fn read_bulk(&mut self, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        trace!(bytes = buf.len(), "bulk OUT: reading payload");
        self.bulk_out
            .read_exact(buf)
            .await
            .context("read payload from bulk OUT")?;
        trace!("bulk OUT: payload received");
        Ok(())
    }

    pub async fn write_bulk(&mut self, buf: &[u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        trace!(bytes = buf.len(), "bulk IN: writing payload");
        self.bulk_in
            .write_all(buf)
            .await
            .context("write payload to bulk IN")?;
        self.bulk_in.flush().await.context("flush bulk IN")
    }

    pub async fn read_bulk_buffer(&mut self, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let len = buf.len();
        match self.buffers.as_mut() {
            Some(pool) => {
                trace!(bytes = len, "bulk OUT: reading payload via buffer pool");
                let mut handle = pool.checkout();
                let result = match handle {
                    BufferHandle::Dma(_) => {
                        self.queue_dmabuf_transfer(self.bulk_out.as_raw_fd(), handle.len(), &handle)
                            .await
                    }
                    BufferHandle::Copy(_) => self.read_bulk(handle.as_mut_slice()).await,
                };
                if result.is_ok() {
                    handle
                        .finish_device_write()
                        .context("invalidate buffer after device write")?;
                    buf.copy_from_slice(&handle.as_slice()[..len]);
                }
                if let Some(pool) = self.buffers.as_mut() {
                    pool.checkin(handle);
                }
                result.context("bulk OUT buffered transfer")
            }
            None => {
                trace!(bytes = len, "bulk OUT: reading payload via read()");
                self.read_bulk(buf).await.context("read bulk payload")
            }
        }
    }

    pub async fn write_bulk_buffer(&mut self, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let len = buf.len();
        match self.buffers.as_mut() {
            Some(pool) => {
                trace!(bytes = len, "bulk IN: writing payload via buffer pool");
                let mut handle = pool.checkout();
                handle.as_mut_slice()[..len].copy_from_slice(&buf[..len]);
                handle
                    .prepare_device_read()
                    .context("prepare buffer before device read")?;
                let result = match handle {
                    BufferHandle::Dma(_) => self
                        .queue_dmabuf_transfer(self.bulk_in.as_raw_fd(), handle.len(), &handle)
                        .await
                        .context("FUNCTIONFS dmabuf transfer (IN)"),
                    BufferHandle::Copy(_) => self.write_bulk(handle.as_slice()).await,
                };
                if let Some(pool) = self.buffers.as_mut() {
                    pool.checkin(handle);
                }
                result.context("bulk IN buffered transfer")
            }
            None => {
                trace!(bytes = len, "bulk IN: writing payload via write()");
                self.write_bulk(buf).await.context("write bulk payload")
            }
        }
    }

    async fn queue_dmabuf_transfer(
        &self,
        endpoint_fd: RawFd,
        len: usize,
        handle: &BufferHandle,
    ) -> Result<()> {
        let buf_fd = match handle {
            BufferHandle::Dma(h) => h.fd(),
            BufferHandle::Copy(_) => {
                return Err(anyhow!("attempted dma transfer with copy buffer"));
            }
        };
        task::spawn_blocking(move || dmabuf_transfer_blocking(endpoint_fd, buf_fd, len))
            .await
            .map_err(|err| anyhow!("dma-buf transfer task failed: {err}"))?
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ControlDirection {
    In,
    Out,
}

fn to_tokio_file(fd: OwnedFd) -> io::Result<File> {
    let std_file = StdFile::from(fd);
    Ok(File::from_std(std_file))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_exports_none() {
        let payload = [0u8; ConfigExportsV0::HEADER_LEN];
        let parsed = ConfigExportsV0::try_from_slice(&payload).expect("parse");
        assert!(parsed.entries().is_empty());
    }

    #[test]
    fn config_exports_single() {
        let mut payload = [0u8; ConfigExportsV0::HEADER_LEN + ConfigExportsV0::ENTRY_LEN];
        payload[2..4].copy_from_slice(&1u16.to_le_bytes());
        payload[8..12].copy_from_slice(&1u32.to_le_bytes()); // export_id
        payload[12..16].copy_from_slice(&4096u32.to_le_bytes());
        payload[16..24].copy_from_slice(&(4096u64 * 8).to_le_bytes());
        let parsed = ConfigExportsV0::try_from_slice(&payload).expect("parse");
        let export = parsed.entries().first().expect("export");
        assert_eq!(export.block_size, 4096);
        assert_eq!(export.size_bytes, 4096 * 8);
    }

    #[test]
    fn config_exports_invalid_flags() {
        let mut payload = [0u8; ConfigExportsV0::HEADER_LEN];
        payload[4] = 1;
        assert!(ConfigExportsV0::try_from_slice(&payload).is_err());
    }
}
