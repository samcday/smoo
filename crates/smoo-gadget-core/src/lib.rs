use anyhow::{Context, Result, anyhow, ensure};
use dma_heap::HeapKind;
use mmap::MemoryMap;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::{ioctl_readwrite, ioctl_write_ptr};
use smoo_proto::{IDENT_LEN, IDENT_REQUEST, Ident, RESPONSE_LEN, Request, Response};
use std::{
    cmp,
    fs::File as StdFile,
    io,
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd},
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    task,
};
use tracing::{debug, trace, warn};

const USB_DIR_IN: u8 = 0x80;
const USB_TYPE_VENDOR: u8 = 0x40;
const USB_RECIP_INTERFACE: u8 = 0x01;
const SMOO_REQ_TYPE: u8 = USB_DIR_IN | USB_TYPE_VENDOR | USB_RECIP_INTERFACE;

const SETUP_STAGE_LEN: usize = 8;
const FUNCTIONFS_EVENT_SIZE: usize = SETUP_STAGE_LEN + 4;
const FUNCTIONFS_IOC_MAGIC: u8 = b'g';
const FUNCTIONFS_DMABUF_ATTACH_NR: u8 = 131;
const FUNCTIONFS_DMABUF_DETACH_NR: u8 = 132;
const FUNCTIONFS_DMABUF_TRANSFER_NR: u8 = 133;

#[repr(C, packed)]
struct UsbFfsDmabufTransferReq {
    fd: libc::c_int,
    flags: u32,
    length: u64,
}

ioctl_write_ptr!(
    ffs_dmabuf_attach,
    FUNCTIONFS_IOC_MAGIC,
    FUNCTIONFS_DMABUF_ATTACH_NR,
    libc::c_int
);

ioctl_write_ptr!(
    ffs_dmabuf_detach,
    FUNCTIONFS_IOC_MAGIC,
    FUNCTIONFS_DMABUF_DETACH_NR,
    libc::c_int
);

ioctl_write_ptr!(
    ffs_dmabuf_transfer,
    FUNCTIONFS_IOC_MAGIC,
    FUNCTIONFS_DMABUF_TRANSFER_NR,
    UsbFfsDmabufTransferReq
);

#[repr(C)]
struct dma_buf_export_sync_file_req {
    flags: u32,
    fd: i32,
}

const DMA_BUF_SYNC_READ: u32 = 1 << 0;
const DMA_BUF_SYNC_WRITE: u32 = 1 << 1;
const DMA_BUF_SYNC_RW: u32 = DMA_BUF_SYNC_READ | DMA_BUF_SYNC_WRITE;

ioctl_readwrite!(
    dma_buf_export_sync_file,
    b'b',
    2,
    dma_buf_export_sync_file_req
);

/// File descriptor bundle for a FunctionFS interface.
pub struct FunctionfsEndpoints {
    pub ep0: OwnedFd,
    pub interrupt_in: OwnedFd,
    pub interrupt_out: OwnedFd,
    pub bulk_in: OwnedFd,
    pub bulk_out: OwnedFd,
}

impl FunctionfsEndpoints {
    pub fn new(
        ep0: OwnedFd,
        interrupt_in: OwnedFd,
        interrupt_out: OwnedFd,
        bulk_in: OwnedFd,
        bulk_out: OwnedFd,
    ) -> Self {
        Self {
            ep0,
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

#[derive(Clone, Copy)]
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
    ep0: Ep0Controller,
    data_plane: GadgetDataPlane,
    ident: Ident,
}

impl SmooGadget {
    pub fn new(endpoints: FunctionfsEndpoints, config: GadgetConfig) -> Result<Self> {
        let FunctionfsEndpoints {
            ep0,
            interrupt_in,
            interrupt_out,
            bulk_in,
            bulk_out,
        } = endpoints;
        Ok(Self {
            ep0: Ep0Controller::new(to_tokio_file(ep0)?),
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

    /// Run the FunctionFS control handshake and reply to the GET_IDENT request.
    pub async fn setup(&mut self) -> Result<()> {
        if self.data_plane.configured {
            return Ok(());
        }
        debug!("waiting for FunctionFS ident handshake");
        loop {
            let event = self
                .ep0
                .next_event()
                .await
                .context("read FunctionFS event")?;
            trace!(?event, "ep0 event");
            match event {
                Ep0Event::Bind => {
                    debug!("FunctionFS bind event received");
                }
                Ep0Event::Unbind => {
                    debug!("FunctionFS unbind event received");
                }
                Ep0Event::Enable => {
                    debug!("FunctionFS interface enabled");
                }
                Ep0Event::Suspend => {
                    debug!("FunctionFS suspend event received");
                }
                Ep0Event::Resume => {
                    debug!("FunctionFS resume event received");
                }
                Ep0Event::Disable => {
                    debug!("FunctionFS disable event received");
                    self.data_plane.configured = false;
                }
                Ep0Event::Setup(setup) => {
                    debug!(
                        request = setup.request(),
                        request_type = setup.request_type(),
                        length = setup.length(),
                        "FunctionFS setup request"
                    );
                    if self.handle_setup_request(setup).await? {
                        self.data_plane.configured = true;
                        debug!("FunctionFS ident handshake complete");
                        return Ok(());
                    }
                }
            }
        }
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

    async fn handle_setup_request(&mut self, setup: SetupPacket) -> Result<bool> {
        if setup.request() == IDENT_REQUEST && setup.request_type() == SMOO_REQ_TYPE {
            ensure!(
                setup.direction() == ControlDirection::In,
                "GET_IDENT must be an IN transfer"
            );
            ensure!(
                setup.length() as usize >= IDENT_LEN,
                "GET_IDENT length too small"
            );
            let ident = self.ident.encode();
            let len = cmp::min(setup.length() as usize, ident.len());
            self.ep0
                .write_in(&ident[..len])
                .await
                .context("reply to GET_IDENT")?;
            return Ok(true);
        }

        if setup.request_type() & USB_DIR_IN == 0 && setup.length() == 0 {
            trace!(
                request = setup.request(),
                "acknowledging status-only control request"
            );
            self.ep0
                .write_in(&[])
                .await
                .context("ack control status stage")?;
            return Ok(false);
        }

        warn!(
            request = setup.request(),
            request_type = setup.request_type(),
            length = setup.length(),
            "unsupported setup request"
        );
        Err(anyhow!(
            "unsupported setup request {:#x} type {:#x}",
            setup.request(),
            setup.request_type()
        ))
    }

    /// Access the raw EP0 controller for custom control-plane handling.
    pub fn ep0_mut(&mut self) -> &mut Ep0Controller {
        &mut self.ep0
    }

    /// Access the data-plane controller directly.
    pub fn data_plane_mut(&mut self) -> &mut GadgetDataPlane {
        &mut self.data_plane
    }
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
    configured: bool,
    dma_scratch: Option<FunctionfsDmaScratch>,
}

impl GadgetDataPlane {
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
        let dma_scratch = if let Some(heap) = dma_heap {
            let slots = queue_count as usize * queue_depth as usize;
            Some(
                FunctionfsDmaScratch::new(
                    bulk_in.as_raw_fd(),
                    bulk_out.as_raw_fd(),
                    slots,
                    max_io_bytes,
                    heap.to_heap_kind(),
                )
                .context("init DMA scratch buffers")?,
            )
        } else {
            None
        };
        Ok(Self {
            interrupt_in: to_tokio_file(interrupt_in)?,
            interrupt_out: to_tokio_file(interrupt_out)?,
            bulk_in: to_tokio_file(bulk_in)?,
            bulk_out: to_tokio_file(bulk_out)?,
            configured: false,
            dma_scratch,
        })
    }

    pub async fn send_request(&mut self, request: Request) -> Result<()> {
        ensure!(self.configured, "gadget not configured");
        let encoded = request.encode();
        self.interrupt_in
            .write_all(&encoded)
            .await
            .context("write request to interrupt IN")?;
        self.interrupt_in
            .flush()
            .await
            .context("flush interrupt IN")?;
        Ok(())
    }

    pub async fn read_response(&mut self) -> Result<Response> {
        ensure!(self.configured, "gadget not configured");
        let mut buf = [0u8; RESPONSE_LEN];
        self.interrupt_out
            .read_exact(&mut buf)
            .await
            .context("read response from interrupt OUT")?;
        Response::try_from(buf.as_slice()).map_err(|err| anyhow!("decode response: {err}"))
    }

    pub async fn read_bulk(&mut self, buf: &mut [u8]) -> Result<()> {
        ensure!(self.configured, "gadget not configured");
        if buf.is_empty() {
            return Ok(());
        }
        self.bulk_out
            .read_exact(buf)
            .await
            .context("read payload from bulk OUT")?;
        Ok(())
    }

    pub async fn write_bulk(&mut self, buf: &[u8]) -> Result<()> {
        ensure!(self.configured, "gadget not configured");
        if buf.is_empty() {
            return Ok(());
        }
        self.bulk_in
            .write_all(buf)
            .await
            .context("write payload to bulk IN")?;
        self.bulk_in.flush().await.context("flush bulk IN")
    }

    pub async fn read_bulk_buffer(&mut self, buf: &mut [u8]) -> Result<()> {
        ensure!(self.configured, "gadget not configured");
        if buf.is_empty() {
            return Ok(());
        }
        let len = buf.len();
        if self.dma_scratch.is_some() {
            let mut slot = {
                let scratch = self.dma_scratch.as_mut().unwrap();
                scratch
                    .checkout_out()
                    .context("checkout bulk OUT DMA buffer")?
            };
            let result = self
                .queue_dmabuf_transfer(self.bulk_out.as_raw_fd(), slot.fd(), len)
                .await;
            if let Some(scratch) = self.dma_scratch.as_mut() {
                if result.is_ok() {
                    slot.finish_device_write()
                        .context("invalidate DMA buffer after device write")?;
                    buf.copy_from_slice(&slot.as_slice()[..len]);
                }
                scratch.checkin_out(slot);
            }
            result
        } else {
            self.read_bulk(buf).await.context("read bulk payload")
        }
    }

    pub async fn write_bulk_buffer(&mut self, buf: &mut [u8]) -> Result<()> {
        ensure!(self.configured, "gadget not configured");
        if buf.is_empty() {
            return Ok(());
        }
        let len = buf.len();
        if self.dma_scratch.is_some() {
            let mut slot = {
                let scratch = self.dma_scratch.as_mut().unwrap();
                scratch
                    .checkout_in()
                    .context("checkout bulk IN DMA buffer")?
            };
            slot.as_mut_slice()[..len].copy_from_slice(&buf[..len]);
            slot.prepare_device_read()
                .context("flush DMA buffer before device read")?;
            let result = self
                .queue_dmabuf_transfer(self.bulk_in.as_raw_fd(), slot.fd(), len)
                .await
                .context("FUNCTIONFS dmabuf transfer (IN)");
            if let Some(scratch) = self.dma_scratch.as_mut() {
                scratch.checkin_in(slot);
            }
            result
        } else {
            self.write_bulk(buf).await.context("write bulk payload")
        }
    }

    async fn queue_dmabuf_transfer(
        &self,
        endpoint_fd: RawFd,
        buf_fd: RawFd,
        len: usize,
    ) -> Result<()> {
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

fn dmabuf_transfer_blocking(endpoint_fd: RawFd, buf_fd: RawFd, len: usize) -> Result<()> {
    let length = u64::try_from(len).context("dma-buf transfer length exceeds u64")?;
    trace!(endpoint_fd, buf_fd, len, "FUNCTIONFS_DMABUF_TRANSFER begin");
    unsafe {
        ffs_dmabuf_transfer(
            endpoint_fd,
            &UsbFfsDmabufTransferReq {
                fd: buf_fd,
                flags: 0,
                length,
            },
        )
    }
    .map_err(|err| anyhow!("FUNCTIONFS_DMABUF_TRANSFER failed: {err}"))?;
    trace!(
        endpoint_fd,
        buf_fd, len, "FUNCTIONFS_DMABUF_TRANSFER submitted"
    );
    wait_for_dmabuf_completion(buf_fd)
}

fn wait_for_dmabuf_completion(dmabuf_fd: RawFd) -> Result<()> {
    trace!(buf_fd = dmabuf_fd, "DMA_BUF_IOCTL_EXPORT_SYNC_FILE begin");
    let sync_fd = unsafe {
        let mut req = dma_buf_export_sync_file_req {
            flags: DMA_BUF_SYNC_RW,
            fd: -1,
        };
        dma_buf_export_sync_file(dmabuf_fd, &mut req)
            .map_err(|err| anyhow!("DMA_BUF_IOCTL_EXPORT_SYNC_FILE failed: {err}"))?;
        ensure!(req.fd >= 0, "sync file descriptor invalid");
        OwnedFd::from_raw_fd(req.fd)
    };
    trace!(
        buf_fd = dmabuf_fd,
        sync_fd = sync_fd.as_raw_fd(),
        "DMA_BUF_IOCTL_EXPORT_SYNC_FILE complete"
    );

    let mut fds = [PollFd::new(sync_fd.as_fd(), PollFlags::POLLIN)];
    loop {
        trace!(
            sync_fd = sync_fd.as_raw_fd(),
            "polling for dma-buf completion"
        );
        match poll(&mut fds, PollTimeout::NONE) {
            Ok(0) => continue,
            Ok(_) => {
                let revents = fds[0].revents().unwrap_or(PollFlags::empty());
                if revents.contains(PollFlags::POLLERR) {
                    return Err(anyhow!("dma-buf completion poll error"));
                }
                if revents.intersects(PollFlags::POLLIN) {
                    break;
                }
            }
            Err(err) => return Err(err.into()),
        }
    }
    trace!(buf_fd = dmabuf_fd, "dma-buf completion fence signaled");
    Ok(())
}
pub struct FunctionfsDmaScratch {
    bulk_in: DmaEndpointPool,
    bulk_out: DmaEndpointPool,
}

impl FunctionfsDmaScratch {
    fn new(
        bulk_in_fd: RawFd,
        bulk_out_fd: RawFd,
        slot_count: usize,
        buf_len: usize,
        heap_kind: HeapKind,
    ) -> Result<Self> {
        let bulk_in = DmaEndpointPool::new(slot_count, buf_len, heap_kind.clone(), bulk_in_fd)
            .context("init bulk IN DMA scratch")?;
        let bulk_out = DmaEndpointPool::new(slot_count, buf_len, heap_kind, bulk_out_fd)
            .context("init bulk OUT DMA scratch")?;
        Ok(Self { bulk_in, bulk_out })
    }

    fn checkout_in(&mut self) -> Result<DmaEndpointSlot> {
        self.bulk_in
            .checkout()
            .context("checkout bulk IN scratch buffer")
    }

    fn checkin_in(&mut self, slot: DmaEndpointSlot) {
        self.bulk_in.checkin(slot);
    }

    fn checkout_out(&mut self) -> Result<DmaEndpointSlot> {
        self.bulk_out
            .checkout()
            .context("checkout bulk OUT scratch buffer")
    }

    fn checkin_out(&mut self, slot: DmaEndpointSlot) {
        self.bulk_out.checkin(slot);
    }
}

struct DmaEndpointPool {
    slots: Vec<Option<DmaBuffer>>,
    _attachments: EndpointAttachments,
}

impl DmaEndpointPool {
    fn new(
        slot_count: usize,
        buf_len: usize,
        heap_kind: HeapKind,
        endpoint_fd: RawFd,
    ) -> Result<Self> {
        ensure!(slot_count > 0, "DMA scratch slot count must be positive");
        ensure!(buf_len > 0, "DMA scratch buffer length must be positive");
        let heap = dma_heap::Heap::new(heap_kind).context("open DMA heap")?;
        let mut slots = Vec::with_capacity(slot_count);
        for _ in 0..slot_count {
            let fd = heap.allocate(buf_len).context("allocate DMA buffer")?;
            slots.push(Some(DmaBuffer::new(fd, buf_len).context("map DMA buffer")?));
        }
        let mut attachments = EndpointAttachments::new(endpoint_fd);
        for buf in slots.iter().flatten() {
            attachments
                .attach(buf.raw_fd())
                .with_context(|| format!("attach dma-buf {} to endpoint", buf.raw_fd()))?;
        }
        Ok(Self {
            slots,
            _attachments: attachments,
        })
    }

    fn checkout(&mut self) -> Result<DmaEndpointSlot> {
        let (idx, buf) = self
            .slots
            .iter_mut()
            .enumerate()
            .find_map(|(idx, slot)| slot.take().map(|buf| (idx, buf)))
            .context("no DMA scratch buffers available")?;
        Ok(DmaEndpointSlot { idx, buf })
    }

    fn checkin(&mut self, slot: DmaEndpointSlot) {
        let previous = self.slots[slot.idx].replace(slot.buf);
        debug_assert!(previous.is_none(), "DMA scratch slot double freed");
    }
}

struct DmaEndpointSlot {
    idx: usize,
    buf: DmaBuffer,
}

impl DmaEndpointSlot {
    fn fd(&self) -> RawFd {
        self.buf.raw_fd()
    }

    fn as_slice(&self) -> &[u8] {
        self.buf.as_slice()
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buf.as_mut_slice()
    }

    fn prepare_device_read(&mut self) -> Result<()> {
        dma_buf_sync_start(self.fd(), DMA_BUF_SYNC_WRITE_FLAG)?;
        dma_buf_sync_end(self.fd(), DMA_BUF_SYNC_WRITE_FLAG)
    }

    fn finish_device_write(&mut self) -> Result<()> {
        dma_buf_sync_start(self.fd(), DMA_BUF_SYNC_READ_FLAG)?;
        dma_buf_sync_end(self.fd(), DMA_BUF_SYNC_READ_FLAG)
    }
}

struct DmaBuffer {
    fd: OwnedFd,
    map: MemoryMap,
    len: usize,
}

impl DmaBuffer {
    fn new(fd: OwnedFd, len: usize) -> Result<Self> {
        let raw_fd = fd.as_raw_fd();
        let map = MemoryMap::new(
            len,
            &[
                mmap::MapOption::MapReadable,
                mmap::MapOption::MapWritable,
                mmap::MapOption::MapFd(raw_fd),
                mmap::MapOption::MapNonStandardFlags(libc::MAP_SHARED),
            ],
        )
        .map_err(|err| anyhow!("map DMA buffer: {err}"))?;
        Ok(Self { fd, map, len })
    }

    fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.map.data(), self.len) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.map.data(), self.len) }
    }
}

struct EndpointAttachments {
    fd: RawFd,
    attached: Vec<RawFd>,
}

impl EndpointAttachments {
    fn new(fd: RawFd) -> Self {
        Self {
            fd,
            attached: Vec::new(),
        }
    }

    fn attach(&mut self, buf_fd: RawFd) -> Result<()> {
        trace!(
            endpoint_fd = self.fd,
            buf_fd, "FUNCTIONFS_DMABUF_ATTACH begin"
        );
        unsafe { ffs_dmabuf_attach(self.fd, &buf_fd) }
            .map_err(|err| anyhow!(err))
            .with_context(|| format!("FUNCTIONFS_DMABUF_ATTACH failed for fd {buf_fd}"))?;
        trace!(
            endpoint_fd = self.fd,
            buf_fd, "FUNCTIONFS_DMABUF_ATTACH complete"
        );
        self.attached.push(buf_fd);
        Ok(())
    }

    fn detach_all(&mut self) {
        for buf_fd in self.attached.drain(..) {
            trace!(
                endpoint_fd = self.fd,
                buf_fd, "FUNCTIONFS_DMABUF_DETACH begin"
            );
            let res = unsafe { ffs_dmabuf_detach(self.fd, &buf_fd) };
            match res {
                Ok(_) => trace!(
                    endpoint_fd = self.fd,
                    buf_fd, "FUNCTIONFS_DMABUF_DETACH complete"
                ),
                Err(err) => warn!(
                    endpoint_fd = self.fd,
                    buf_fd,
                    error = %err,
                    "FUNCTIONFS_DMABUF_DETACH failed"
                ),
            }
        }
    }
}

impl Drop for EndpointAttachments {
    fn drop(&mut self) {
        self.detach_all();
    }
}

#[repr(C)]
struct DmaBufSync {
    flags: u64,
}

const DMA_BUF_SYNC_NR: u8 = 0;
const DMA_BUF_SYNC_START: u64 = 0 << 2;
const DMA_BUF_SYNC_END: u64 = 1 << 2;
const DMA_BUF_SYNC_READ_FLAG: u64 = 1 << 0;
const DMA_BUF_SYNC_WRITE_FLAG: u64 = 1 << 1;

ioctl_write_ptr!(dma_buf_sync, b'b', DMA_BUF_SYNC_NR, DmaBufSync);

fn dma_buf_sync_call(fd: RawFd, flags: u64) -> Result<()> {
    let req = DmaBufSync { flags };
    trace!(fd, flags, "DMA_BUF_IOCTL_SYNC begin");
    let res = unsafe { dma_buf_sync(fd, &req) };
    match res {
        Ok(0) => {
            trace!(fd, flags, "DMA_BUF_IOCTL_SYNC complete");
            Ok(())
        }
        Ok(code) => Err(anyhow!("DMA_BUF_IOCTL_SYNC unexpected code {code}")),
        Err(err) => {
            warn!(fd, flags, error = %err, "DMA_BUF_IOCTL_SYNC failed");
            Err(anyhow!("DMA_BUF_IOCTL_SYNC failed: {err}"))
        }
    }
}

fn dma_buf_sync_start(fd: RawFd, dir: u64) -> Result<()> {
    dma_buf_sync_call(fd, DMA_BUF_SYNC_START | dir)
}

fn dma_buf_sync_end(fd: RawFd, dir: u64) -> Result<()> {
    dma_buf_sync_call(fd, DMA_BUF_SYNC_END | dir)
}
