use anyhow::{Context, Result, anyhow, ensure};
use dma_heap::HeapKind;
use mmap::MemoryMap;
use nix::{
    ioctl_readwrite, ioctl_write_ptr,
    poll::{PollFd, PollFlags, PollTimeout, poll},
};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use tracing::{trace, warn};

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

/// Scratch DMA-BUF pools for FunctionFS bulk endpoints.
pub(crate) struct FunctionfsDmaScratch {
    bulk_in: DmaEndpointPool,
    bulk_out: DmaEndpointPool,
}

impl FunctionfsDmaScratch {
    pub(crate) fn new(
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

    pub(crate) fn checkout_in(&mut self) -> Result<DmaEndpointSlot> {
        self.bulk_in
            .checkout()
            .context("checkout bulk IN scratch buffer")
    }

    pub(crate) fn checkin_in(&mut self, slot: DmaEndpointSlot) {
        self.bulk_in.checkin(slot);
    }

    pub(crate) fn checkout_out(&mut self) -> Result<DmaEndpointSlot> {
        self.bulk_out
            .checkout()
            .context("checkout bulk OUT scratch buffer")
    }

    pub(crate) fn checkin_out(&mut self, slot: DmaEndpointSlot) {
        self.bulk_out.checkin(slot);
    }
}

pub(crate) fn dmabuf_transfer_blocking(
    endpoint_fd: RawFd,
    buf_fd: RawFd,
    len: usize,
) -> Result<()> {
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

pub(crate) struct DmaEndpointSlot {
    idx: usize,
    buf: DmaBuffer,
}

impl DmaEndpointSlot {
    pub(crate) fn fd(&self) -> RawFd {
        self.buf.raw_fd()
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        self.buf.as_slice()
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buf.as_mut_slice()
    }

    pub(crate) fn prepare_device_read(&mut self) -> Result<()> {
        dma_buf_sync_start(self.fd(), DMA_BUF_SYNC_WRITE_FLAG)?;
        dma_buf_sync_end(self.fd(), DMA_BUF_SYNC_WRITE_FLAG)
    }

    pub(crate) fn finish_device_write(&mut self) -> Result<()> {
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
