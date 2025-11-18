use anyhow::{Context, Result, anyhow, ensure};
use dma_heap::{Heap, HeapKind};
use mmap::{MapError, MapOption, MemoryMap};
use nix::ioctl_write_ptr;
use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::ptr::NonNull;
use std::slice;
use tracing::{trace, warn};

const BUFFER_ALIGNMENT: usize = 4096;

const FUNCTIONFS_IOC_MAGIC: u8 = b'g';
const FUNCTIONFS_DMABUF_ATTACH_NR: u8 = 131;
const FUNCTIONFS_DMABUF_DETACH_NR: u8 = 132;
const DMA_BUF_SYNC_NR: u8 = 0;

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

/// Type-erased buffer handle used throughout the gadget.
pub type BufferHandle = Box<dyn Buffer>;

/// Byte buffer backing a ublk queue slot.
pub trait Buffer: Send {
    /// Returns the logical capacity of the buffer.
    fn len(&self) -> usize;

    /// Returns a stable pointer to the buffer contents.
    fn as_ptr(&self) -> *const u8;

    /// Returns a mutable pointer to the buffer contents.
    fn as_mut_ptr(&self) -> *mut u8;

    /// Returns an immutable slice covering the logical buffer contents.
    fn as_slice(&self) -> &[u8];

    /// Returns a mutable slice covering the logical buffer contents.
    fn as_mut_slice(&mut self) -> &mut [u8];

    /// Returns the dma-buf file descriptor if backed by DMA memory.
    fn dma_fd(&self) -> Option<RawFd> {
        None
    }

    /// Called before the buffer is used as the source of a DMA transfer.
    fn before_device_read(&mut self, _len: usize) -> Result<()> {
        Ok(())
    }

    /// Called after the buffer has been written by a DMA transfer.
    fn after_device_write(&mut self, _len: usize) -> Result<()> {
        Ok(())
    }
}

/// Provides temporary byte buffers keyed by ublk queue + tag.
pub trait BufferPool: Send {
    /// Returns the capacity of each buffer in bytes.
    fn buffer_len(&self) -> usize;

    /// Returns the raw pointers for every queue/tag slot in queue-major order.
    ///
    /// These pointers stay stable for the lifetime of the pool.
    fn buffer_ptrs(&self) -> Result<Vec<*mut u8>>;

    /// Checks out the buffer assigned to `queue_id`/`tag`.
    fn checkout(&mut self, queue_id: u16, tag: u16) -> Result<BufferHandle>;

    /// Returns the buffer to the pool.
    fn checkin(&mut self, queue_id: u16, tag: u16, buf: BufferHandle);
}

/// Page-aligned byte buffer implemented with regular virtual memory.
pub struct VecBuffer {
    ptr: NonNull<u8>,
    len: usize,
}

unsafe impl Send for VecBuffer {}
unsafe impl Sync for VecBuffer {}

impl VecBuffer {
    pub fn new(len: usize) -> Result<Self> {
        ensure!(len > 0, "buffer length must be positive");
        let layout = Layout::from_size_align(len, BUFFER_ALIGNMENT).context("buffer layout")?;
        // Safety: layout has non-zero size and alignment validated above.
        let ptr = unsafe { alloc_zeroed(layout) };
        let ptr = NonNull::new(ptr).context("allocate buffer")?;
        Ok(Self { ptr, len })
    }

    fn layout(&self) -> Layout {
        Layout::from_size_align(self.len, BUFFER_ALIGNMENT).expect("buffer layout")
    }
}

impl Buffer for VecBuffer {
    fn len(&self) -> usize {
        self.len
    }

    fn as_ptr(&self) -> *const u8 {
        self.ptr.as_ptr()
    }

    fn as_mut_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for VecBuffer {
    fn drop(&mut self) {
        unsafe {
            dealloc(self.ptr.as_ptr(), self.layout());
        }
    }
}

/// BufferPool backed by a Vec of reusable buffers.
pub struct VecBufferPool {
    slots: Vec<Option<BufferHandle>>,
    queue_count: usize,
    queue_depth: usize,
    buf_len: usize,
}

impl VecBufferPool {
    pub fn new(queue_count: u16, queue_depth: u16, buf_len: usize) -> Result<Self> {
        ensure!(buf_len > 0, "buffer length must be positive");
        let queue_count = queue_count as usize;
        let queue_depth = queue_depth as usize;
        let total = queue_count
            .checked_mul(queue_depth)
            .context("buffer pool size overflow")?;
        let mut slots = Vec::with_capacity(total);
        for _ in 0..total {
            let buf: BufferHandle = Box::new(VecBuffer::new(buf_len)?);
            slots.push(Some(buf));
        }
        Ok(Self {
            slots,
            queue_count,
            queue_depth,
            buf_len,
        })
    }

    fn index(&self, queue_id: u16, tag: u16) -> Result<usize> {
        let queue = queue_id as usize;
        let tag = tag as usize;
        ensure!(queue < self.queue_count, "queue id out of range");
        ensure!(tag < self.queue_depth, "tag out of range");
        Ok(queue * self.queue_depth + tag)
    }
}

impl BufferPool for VecBufferPool {
    fn buffer_len(&self) -> usize {
        self.buf_len
    }

    fn buffer_ptrs(&self) -> Result<Vec<*mut u8>> {
        self.slots
            .iter()
            .map(|slot| {
                slot.as_ref()
                    .map(|buf| buf.as_mut_ptr())
                    .context("buffer slot missing while collecting pointers")
            })
            .collect()
    }

    fn checkout(&mut self, queue_id: u16, tag: u16) -> Result<BufferHandle> {
        let idx = self.index(queue_id, tag)?;
        self.slots[idx].take().context("buffer already checked out")
    }

    fn checkin(&mut self, queue_id: u16, tag: u16, buf: BufferHandle) {
        debug_assert!(
            buf.len() == self.buf_len,
            "buffer length mismatch during checkin"
        );
        let idx = self
            .index(queue_id, tag)
            .expect("buffer index out of range");
        let previous = self.slots[idx].replace(buf);
        debug_assert!(previous.is_none(), "buffer slot occupied during checkin");
    }
}

/// Scratch DMA-BUF pool dedicated to a single FunctionFS endpoint.
pub struct DmaEndpointPool {
    buffers: Vec<Option<DmaBuffer>>,
    attachments: EndpointAttachments,
}

pub struct DmaEndpointSlot {
    idx: usize,
    buf: DmaBuffer,
}

impl DmaEndpointPool {
    pub fn new(
        slot_count: usize,
        buf_len: usize,
        heap_kind: HeapKind,
        endpoint_fd: RawFd,
    ) -> Result<Self> {
        ensure!(buf_len > 0, "buffer length must be positive");
        let heap = Heap::new(heap_kind).context("open DMA heap")?;
        let mut buffers = Vec::with_capacity(slot_count);
        for _ in 0..slot_count {
            let fd = heap.allocate(buf_len).context("allocate dma-buf")?;
            buffers.push(Some(DmaBuffer::new(fd, buf_len).context("map dma-buf")?));
        }
        let mut attachments = EndpointAttachments::new(endpoint_fd);
        for buf in buffers.iter().flatten() {
            attachments
                .attach(buf.raw_fd())
                .with_context(|| format!("attach dma-buf {} to endpoint", buf.raw_fd()))?;
        }
        Ok(Self {
            buffers,
            attachments,
        })
    }

    pub fn checkout(&mut self) -> Result<DmaEndpointSlot> {
        let (idx, buf) = self
            .buffers
            .iter_mut()
            .enumerate()
            .find_map(|(idx, slot)| slot.take().map(|buf| (idx, buf)))
            .context("no DMA scratch buffers available")?;
        Ok(DmaEndpointSlot { idx, buf })
    }

    pub fn checkin(&mut self, slot: DmaEndpointSlot) {
        let prev = self.buffers[slot.idx].replace(slot.buf);
        debug_assert!(prev.is_none(), "DMA scratch slot already occupied");
    }
}

impl DmaEndpointSlot {
    pub fn fd(&self) -> RawFd {
        self.buf.raw_fd()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.buf.as_slice()
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buf.as_mut_slice()
    }

    pub fn prepare_device_read(&mut self) -> Result<()> {
        dma_buf_sync_start(self.fd(), DMA_BUF_SYNC_WRITE_FLAG)?;
        dma_buf_sync_end(self.fd(), DMA_BUF_SYNC_WRITE_FLAG)
    }

    pub fn finish_device_write(&mut self) -> Result<()> {
        dma_buf_sync_start(self.fd(), DMA_BUF_SYNC_READ_FLAG)?;
        dma_buf_sync_end(self.fd(), DMA_BUF_SYNC_READ_FLAG)
    }
}

impl Drop for DmaEndpointPool {
    fn drop(&mut self) {
        self.attachments.detach_all();
    }
}

struct DmaBuffer {
    fd: OwnedFd,
    map: MemoryMap,
    len: usize,
}

unsafe impl Send for DmaBuffer {}
unsafe impl Sync for DmaBuffer {}

impl DmaBuffer {
    fn new(fd: OwnedFd, len: usize) -> Result<Self> {
        ensure!(len > 0, "buffer length must be positive");
        let raw_fd = fd.as_raw_fd();
        let map = MemoryMap::new(
            len,
            &[
                MapOption::MapReadable,
                MapOption::MapWritable,
                MapOption::MapFd(raw_fd),
                MapOption::MapNonStandardFlags(libc::MAP_SHARED),
            ],
        )
        .map_err(|err| map_err_to_anyhow(err, "map dma-buf memory"))?;
        Ok(Self { fd, map, len })
    }

    fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl Buffer for DmaBuffer {
    fn len(&self) -> usize {
        self.len
    }

    fn as_ptr(&self) -> *const u8 {
        self.map.data()
    }

    fn as_mut_ptr(&self) -> *mut u8 {
        self.map.data()
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.map.data(), self.len) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.map.data(), self.len) }
    }

    fn dma_fd(&self) -> Option<RawFd> {
        Some(self.fd.as_raw_fd())
    }

    fn before_device_read(&mut self, _len: usize) -> Result<()> {
        dma_buf_sync_start(self.fd.as_raw_fd(), DMA_BUF_SYNC_WRITE_FLAG)?;
        dma_buf_sync_end(self.fd.as_raw_fd(), DMA_BUF_SYNC_WRITE_FLAG)
    }

    fn after_device_write(&mut self, _len: usize) -> Result<()> {
        dma_buf_sync_start(self.fd.as_raw_fd(), DMA_BUF_SYNC_READ_FLAG)?;
        dma_buf_sync_end(self.fd.as_raw_fd(), DMA_BUF_SYNC_READ_FLAG)
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
        self.attached.push(buf_fd);
        trace!(
            endpoint_fd = self.fd,
            buf_fd, "FUNCTIONFS_DMABUF_ATTACH complete"
        );
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

fn map_err_to_anyhow(err: MapError, context: &str) -> anyhow::Error {
    anyhow!("{context}: {err}")
}

fn dma_buf_sync_call(fd: RawFd, flags: u64) -> Result<()> {
    let req = DmaBufSync { flags };
    trace!(fd, flags, "DMA_BUF_IOCTL_SYNC begin");
    let res = unsafe { dma_buf_sync(fd, &req) };
    match res {
        Ok(_) => {
            trace!(fd, flags, "DMA_BUF_IOCTL_SYNC complete");
            Ok(())
        }
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
#[repr(C)]
struct DmaBufSync {
    flags: u64,
}

const DMA_BUF_SYNC_START: u64 = 0 << 2;
const DMA_BUF_SYNC_END: u64 = 1 << 2;
const DMA_BUF_SYNC_READ_FLAG: u64 = 1 << 0;
const DMA_BUF_SYNC_WRITE_FLAG: u64 = 1 << 1;

ioctl_write_ptr!(dma_buf_sync, b'b', DMA_BUF_SYNC_NR, DmaBufSync);
