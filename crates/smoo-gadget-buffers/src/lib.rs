use anyhow::{Context, Result, ensure};
use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;

const BUFFER_ALIGNMENT: usize = 4096;

/// Owns a page-aligned byte buffer whose address stays stable for its lifetime.
pub struct Buffer {
    ptr: NonNull<u8>,
    len: usize,
}

unsafe impl Send for Buffer {}
unsafe impl Sync for Buffer {}

impl Buffer {
    pub fn new(len: usize) -> Result<Self> {
        ensure!(len > 0, "buffer length must be positive");
        let layout = Layout::from_size_align(len, BUFFER_ALIGNMENT).context("buffer layout")?;
        // Safety: layout has non-zero size and alignment validated above.
        let ptr = unsafe { alloc_zeroed(layout) };
        let ptr = NonNull::new(ptr).context("allocate buffer")?;
        Ok(Self { ptr, len })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    fn layout(&self) -> Layout {
        Layout::from_size_align(self.len, BUFFER_ALIGNMENT).expect("buffer layout")
    }
}

impl Deref for Buffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl DerefMut for Buffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        unsafe {
            dealloc(self.ptr.as_ptr(), self.layout());
        }
    }
}

/// Provides temporary byte buffers keyed by ublk queue + tag.
pub trait BufferPool {
    /// Returns the capacity of each buffer in bytes.
    fn buffer_len(&self) -> usize;

    /// Checks out the buffer assigned to `queue_id`/`tag`.
    fn checkout(&mut self, queue_id: u16, tag: u16) -> Result<Buffer>;

    /// Returns the buffer to the pool.
    fn checkin(&mut self, queue_id: u16, tag: u16, buf: Buffer);
}

/// BufferPool backed by a Vec of reusable `Vec<u8>` slots.
pub struct VecBufferPool {
    slots: Vec<Option<Buffer>>,
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
            slots.push(Some(Buffer::new(buf_len)?));
        }
        Ok(Self {
            slots,
            queue_count,
            queue_depth,
            buf_len,
        })
    }

    /// Returns the raw pointers for every queue/tag slot in queue-major order.
    ///
    /// These pointers stay stable for the lifetime of the pool because the
    /// backing `Vec<u8>` allocations never change capacity.
    pub fn buffer_ptrs(&self) -> Result<Vec<*mut u8>> {
        self.slots
            .iter()
            .map(|slot| {
                slot.as_ref()
                    .map(|buf| buf.as_mut_ptr())
                    .context("buffer slot missing while collecting pointers")
            })
            .collect()
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

    fn checkout(&mut self, queue_id: u16, tag: u16) -> Result<Buffer> {
        let idx = self.index(queue_id, tag)?;
        self.slots[idx].take().context("buffer already checked out")
    }

    fn checkin(&mut self, queue_id: u16, tag: u16, buf: Buffer) {
        let idx = self
            .index(queue_id, tag)
            .expect("buffer index out of range");
        let previous = self.slots[idx].replace(buf);
        debug_assert!(previous.is_none(), "buffer slot occupied during checkin");
    }
}
