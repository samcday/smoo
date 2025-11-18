use anyhow::{Context, Result, anyhow, ensure};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::{ioctl_readwrite, ioctl_write_ptr};
use smoo_gadget_buffers::{Buffer, BufferPool};
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
const FUNCTIONFS_DMABUF_TRANSFER_NR: u8 = 133;

#[repr(C, packed)]
struct UsbFfsDmabufTransferReq {
    fd: libc::c_int,
    flags: u32,
    length: u64,
}

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

/// Gadget configuration parameters that stay constant while the device is active.
#[derive(Clone, Copy)]
pub struct GadgetConfig {
    pub ident: Ident,
    pub queue_count: u16,
    pub queue_depth: u16,
    pub max_io_bytes: usize,
}

impl GadgetConfig {
    pub fn new(ident: Ident, queue_count: u16, queue_depth: u16, max_io_bytes: usize) -> Self {
        Self {
            ident,
            queue_count,
            queue_depth,
            max_io_bytes,
        }
    }
}

/// High-level FunctionFS gadget driver.
pub struct SmooGadget {
    ep0: File,
    interrupt_in: File,
    interrupt_out: File,
    #[allow(dead_code)]
    bulk_in: File,
    #[allow(dead_code)]
    bulk_out: File,
    ident: Ident,
    configured: bool,
    buffer_pool: Box<dyn BufferPool>,
}

impl SmooGadget {
    pub fn new(
        endpoints: FunctionfsEndpoints,
        config: GadgetConfig,
        buffer_pool: Box<dyn BufferPool>,
    ) -> Result<Self> {
        ensure!(
            buffer_pool.buffer_len() == config.max_io_bytes,
            "buffer pool length mismatch"
        );
        Ok(Self {
            ep0: to_tokio_file(endpoints.ep0)?,
            interrupt_in: to_tokio_file(endpoints.interrupt_in)?,
            interrupt_out: to_tokio_file(endpoints.interrupt_out)?,
            bulk_in: to_tokio_file(endpoints.bulk_in)?,
            bulk_out: to_tokio_file(endpoints.bulk_out)?,
            ident: config.ident,
            configured: false,
            buffer_pool,
        })
    }

    /// Run the FunctionFS control handshake and reply to the GET_IDENT request.
    pub async fn setup(&mut self) -> Result<()> {
        if self.configured {
            return Ok(());
        }
        debug!("waiting for FunctionFS ident handshake");
        loop {
            let event = self.next_event().await.context("read FunctionFS event")?;
            trace!(?event, "ep0 event");
            match event {
                FunctionfsEvent::Bind => {
                    debug!("FunctionFS bind event received");
                }
                FunctionfsEvent::Unbind => {
                    debug!("FunctionFS unbind event received");
                }
                FunctionfsEvent::Enable => {
                    debug!("FunctionFS interface enabled");
                }
                FunctionfsEvent::Suspend => {
                    debug!("FunctionFS suspend event received");
                }
                FunctionfsEvent::Resume => {
                    debug!("FunctionFS resume event received");
                }
                FunctionfsEvent::Disable => {
                    debug!("FunctionFS disable event received");
                    self.configured = false;
                }
                FunctionfsEvent::Setup(setup) => {
                    debug!(
                        request = setup.request,
                        request_type = setup.request_type,
                        length = setup.length,
                        "FunctionFS setup request"
                    );
                    if self.handle_setup_request(setup).await? {
                        self.configured = true;
                        debug!("FunctionFS ident handshake complete");
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Send a Request message to the host over the interrupt IN endpoint.
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

    /// Receive a Response message from the host over the interrupt OUT endpoint.
    pub async fn read_response(&mut self) -> Result<Response> {
        ensure!(self.configured, "gadget not configured");
        let mut buf = [0u8; RESPONSE_LEN];
        self.interrupt_out
            .read_exact(&mut buf)
            .await
            .context("read response from interrupt OUT")?;
        Response::try_from(buf.as_slice()).map_err(|err| anyhow!("decode response: {err}"))
    }

    /// Read a bulk payload from the host (bulk OUT → gadget).
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

    /// Write a bulk payload to the host (bulk IN → host).
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

    /// Read a bulk payload directly into a pooled buffer, using DMA-BUF when available.
    pub async fn read_bulk_buffer(&mut self, buf: &mut dyn Buffer, len: usize) -> Result<()> {
        ensure!(self.configured, "gadget not configured");
        if len == 0 {
            return Ok(());
        }
        if let Some(fd) = buf.dma_fd() {
            self.queue_dmabuf_transfer(self.bulk_out.as_raw_fd(), fd, len)
                .await
                .context("FUNCTIONFS dmabuf transfer (OUT)")?;
            buf.after_device_write(len)?;
            Ok(())
        } else {
            self.read_bulk(&mut buf.as_mut_slice()[..len])
                .await
                .context("read bulk payload")
        }
    }

    /// Write a bulk payload from a pooled buffer, using DMA-BUF when available.
    pub async fn write_bulk_buffer(&mut self, buf: &dyn Buffer, len: usize) -> Result<()> {
        ensure!(self.configured, "gadget not configured");
        if len == 0 {
            return Ok(());
        }
        if let Some(fd) = buf.dma_fd() {
            buf.before_device_read(len)?;
            self.queue_dmabuf_transfer(self.bulk_in.as_raw_fd(), fd, len)
                .await
                .context("FUNCTIONFS dmabuf transfer (IN)")?;
            Ok(())
        } else {
            self.write_bulk(&buf.as_slice()[..len])
                .await
                .context("write bulk payload")
        }
    }

    /// Access the shared Vec-backed buffer pool for bulk transfers.
    pub fn buffer_pool(&mut self) -> &mut dyn BufferPool {
        self.buffer_pool.as_mut()
    }

    async fn next_event(&mut self) -> Result<FunctionfsEvent> {
        let mut buf = [0u8; FUNCTIONFS_EVENT_SIZE];
        self.ep0
            .read_exact(&mut buf)
            .await
            .context("read ep0 event")?;
        FunctionfsEvent::from_bytes(buf)
    }

    async fn handle_setup_request(&mut self, setup: UsbControlRequest) -> Result<bool> {
        if setup.request == IDENT_REQUEST && setup.request_type == SMOO_REQ_TYPE {
            ensure!(
                setup.direction() == ControlDirection::In,
                "GET_IDENT must be an IN transfer"
            );
            ensure!(
                setup.length as usize >= IDENT_LEN,
                "GET_IDENT length too small"
            );
            let ident = self.ident.encode();
            let len = cmp::min(setup.length as usize, ident.len());
            self.write_ep0(&ident[..len])
                .await
                .context("reply to GET_IDENT")?;
            return Ok(true);
        }

        if setup.request_type & USB_DIR_IN == 0 && setup.length == 0 {
            trace!(
                request = setup.request,
                "acknowledging status-only control request"
            );
            self.write_ep0(&[])
                .await
                .context("ack control status stage")?;
            return Ok(false);
        }

        warn!(
            request = setup.request,
            request_type = setup.request_type,
            length = setup.length,
            "unsupported setup request"
        );
        Err(anyhow!(
            "unsupported setup request {:#x} type {:#x}",
            setup.request,
            setup.request_type
        ))
    }

    async fn write_ep0(&mut self, data: &[u8]) -> Result<()> {
        self.ep0.write_all(data).await.context("write ep0 data")?;
        self.ep0.flush().await.context("flush ep0")?;
        Ok(())
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

#[derive(Clone, Copy, Debug)]
struct UsbControlRequest {
    request_type: u8,
    request: u8,
    #[allow(dead_code)]
    value: u16,
    #[allow(dead_code)]
    index: u16,
    length: u16,
}

impl UsbControlRequest {
    fn from_bytes(bytes: [u8; SETUP_STAGE_LEN]) -> Self {
        let value = u16::from_le_bytes([bytes[2], bytes[3]]);
        let index = u16::from_le_bytes([bytes[4], bytes[5]]);
        let length = u16::from_le_bytes([bytes[6], bytes[7]]);
        Self {
            request_type: bytes[0],
            request: bytes[1],
            value,
            index,
            length,
        }
    }

    fn direction(&self) -> ControlDirection {
        if self.request_type & USB_DIR_IN != 0 {
            ControlDirection::In
        } else {
            ControlDirection::Out
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum FunctionfsEvent {
    Bind,
    Unbind,
    Enable,
    Disable,
    Setup(UsbControlRequest),
    Suspend,
    Resume,
}

impl FunctionfsEvent {
    fn from_bytes(bytes: [u8; FUNCTIONFS_EVENT_SIZE]) -> Result<Self> {
        let event_type = FunctionfsEventType::try_from(bytes[SETUP_STAGE_LEN])?;
        Ok(match event_type {
            FunctionfsEventType::Bind => FunctionfsEvent::Bind,
            FunctionfsEventType::Unbind => FunctionfsEvent::Unbind,
            FunctionfsEventType::Enable => FunctionfsEvent::Enable,
            FunctionfsEventType::Disable => FunctionfsEvent::Disable,
            FunctionfsEventType::Suspend => FunctionfsEvent::Suspend,
            FunctionfsEventType::Resume => FunctionfsEvent::Resume,
            FunctionfsEventType::Setup => {
                let mut setup_bytes = [0u8; SETUP_STAGE_LEN];
                setup_bytes.copy_from_slice(&bytes[..SETUP_STAGE_LEN]);
                FunctionfsEvent::Setup(UsbControlRequest::from_bytes(setup_bytes))
            }
        })
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
enum FunctionfsEventType {
    Bind = 0,
    Unbind = 1,
    Enable = 2,
    Disable = 3,
    Setup = 4,
    Suspend = 5,
    Resume = 6,
}

impl TryFrom<u8> for FunctionfsEventType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(FunctionfsEventType::Bind),
            1 => Ok(FunctionfsEventType::Unbind),
            2 => Ok(FunctionfsEventType::Enable),
            3 => Ok(FunctionfsEventType::Disable),
            4 => Ok(FunctionfsEventType::Setup),
            5 => Ok(FunctionfsEventType::Suspend),
            6 => Ok(FunctionfsEventType::Resume),
            other => Err(anyhow!("unknown FunctionFS event type {other}")),
        }
    }
}

fn to_tokio_file(fd: OwnedFd) -> io::Result<File> {
    let std_file = StdFile::from(fd);
    Ok(File::from_std(std_file))
}

fn dmabuf_transfer_blocking(endpoint_fd: RawFd, buf_fd: RawFd, len: usize) -> Result<()> {
    let length = u64::try_from(len).context("dma-buf transfer length exceeds u64")?;
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
    wait_for_dmabuf_completion(buf_fd)
}

fn wait_for_dmabuf_completion(dmabuf_fd: RawFd) -> Result<()> {
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

    let mut fds = [PollFd::new(sync_fd.as_fd(), PollFlags::POLLIN)];
    loop {
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
    Ok(())
}
