use anyhow::{Context, Result, anyhow, ensure};
use dma_heap::HeapKind;
use smoo_proto::{IDENT_LEN, IDENT_REQUEST, Ident, RESPONSE_LEN, Request, Response};
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
use tracing::{debug, trace, warn};

mod dma;

use crate::dma::{FunctionfsDmaScratch, dmabuf_transfer_blocking};

const USB_DIR_IN: u8 = 0x80;
const USB_TYPE_VENDOR: u8 = 0x40;
const USB_RECIP_INTERFACE: u8 = 0x01;
const SMOO_REQ_TYPE: u8 = USB_DIR_IN | USB_TYPE_VENDOR | USB_RECIP_INTERFACE;
/// bmRequestType for CONFIG_EXPORTS (OUT/vendor/interface).
pub const SMOO_CONFIG_REQ_TYPE: u8 = USB_TYPE_VENDOR | USB_RECIP_INTERFACE;
/// Vendor control bRequest for CONFIG_EXPORTS.
pub const CONFIG_EXPORTS_REQUEST: u8 = 0x02;

/// Parsed representation of the v0 CONFIG_EXPORTS payload (single export max).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigExportsV0 {
    export: Option<SingleExport>,
}

impl ConfigExportsV0 {
    /// Number of bytes in the encoded payload.
    pub const ENCODED_LEN: usize = 28;

    pub fn parse(data: &[u8]) -> Result<Self> {
        ensure!(
            data.len() == Self::ENCODED_LEN,
            "CONFIG_EXPORTS payload must be {} bytes",
            Self::ENCODED_LEN
        );
        let version = u16::from_le_bytes([data[0], data[1]]);
        ensure!(version == 0, "unsupported CONFIG_EXPORTS version {version}");
        let count = u16::from_le_bytes([data[2], data[3]]);
        ensure!(count <= 1, "CONFIG_EXPORTS count must be 0 or 1");
        let flags = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        ensure!(flags == 0, "CONFIG_EXPORTS header flags must be zero");
        let block_size = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let size_bytes = u64::from_le_bytes([
            data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19],
        ]);
        let reserved0 = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
        let reserved1 = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
        ensure!(
            reserved0 == 0 && reserved1 == 0,
            "reserved fields must be zero"
        );
        let export = if count == 0 {
            None
        } else {
            ensure!(
                block_size.is_power_of_two(),
                "block size must be power-of-two"
            );
            ensure!(
                (512..=65536).contains(&block_size),
                "block size {block_size} out of supported range"
            );
            if size_bytes != 0 {
                ensure!(
                    size_bytes.is_multiple_of(block_size as u64),
                    "size_bytes must be multiple of block_size"
                );
            }
            Some(SingleExport {
                block_size,
                size_bytes,
            })
        };
        Ok(Self { export })
    }

    /// Returns the desired export, if any.
    pub fn export(&self) -> Option<SingleExport> {
        self.export.clone()
    }
}

/// Parameters describing a single export entry in v0 CONFIG_EXPORTS payloads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleExport {
    pub block_size: u32,
    pub size_bytes: u64,
}

const SETUP_STAGE_LEN: usize = 8;
const FUNCTIONFS_EVENT_SIZE: usize = SETUP_STAGE_LEN + 4;

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
    ep0: Option<Ep0Controller>,
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
            ep0: Some(Ep0Controller::new(to_tokio_file(ep0)?)),
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
            let event = {
                let ep0 = self
                    .ep0
                    .as_mut()
                    .context("FunctionFS ep0 controller unavailable")?;
                ep0.next_event().await.context("read FunctionFS event")?
            };
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
                    if SmooGadget::handle_setup_request(
                        self.ident,
                        self.ep0
                            .as_mut()
                            .context("FunctionFS ep0 controller unavailable")?,
                        setup,
                    )
                    .await?
                    {
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

    async fn handle_setup_request(
        ident: Ident,
        ep0: &mut Ep0Controller,
        setup: SetupPacket,
    ) -> Result<bool> {
        if setup.request() == IDENT_REQUEST && setup.request_type() == SMOO_REQ_TYPE {
            ensure!(
                setup.direction() == ControlDirection::In,
                "GET_IDENT must be an IN transfer"
            );
            ensure!(
                setup.length() as usize >= IDENT_LEN,
                "GET_IDENT length too small"
            );
            let ident = ident.encode();
            let len = cmp::min(setup.length() as usize, ident.len());
            ep0.write_in(&ident[..len])
                .await
                .context("reply to GET_IDENT")?;
            return Ok(true);
        }

        if setup.request_type() & USB_DIR_IN == 0 && setup.length() == 0 {
            trace!(
                request = setup.request(),
                "acknowledging status-only control request"
            );
            ep0.write_in(&[])
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
    pub fn ep0_mut(&mut self) -> Option<&mut Ep0Controller> {
        self.ep0.as_mut()
    }

    /// Take ownership of the EP0 controller, preventing further use by [`SmooGadget`].
    pub fn take_ep0_controller(&mut self) -> Option<Ep0Controller> {
        self.ep0.take()
    }

    /// Access the data-plane controller directly.
    pub fn data_plane_mut(&mut self) -> &mut GadgetDataPlane {
        &mut self.data_plane
    }

    /// Current IDENT response advertised by the gadget.
    pub fn ident(&self) -> Ident {
        self.ident
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_exports_none() {
        let payload = [0u8; ConfigExportsV0::ENCODED_LEN];
        let parsed = ConfigExportsV0::parse(&payload).expect("parse");
        assert!(parsed.export().is_none());
    }

    #[test]
    fn config_exports_single() {
        let mut payload = [0u8; ConfigExportsV0::ENCODED_LEN];
        payload[2] = 1;
        payload[8..12].copy_from_slice(&4096u32.to_le_bytes());
        payload[12..20].copy_from_slice(&(4096u64 * 8).to_le_bytes());
        let parsed = ConfigExportsV0::parse(&payload).expect("parse");
        let export = parsed.export().expect("export");
        assert_eq!(export.block_size, 4096);
        assert_eq!(export.size_bytes, 4096 * 8);
    }

    #[test]
    fn config_exports_invalid_flags() {
        let mut payload = [0u8; ConfigExportsV0::ENCODED_LEN];
        payload[4] = 1;
        assert!(ConfigExportsV0::parse(&payload).is_err());
    }
}
