use anyhow::{Context, Result, anyhow, ensure};
use std::cell::UnsafeCell;
use std::io;
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicBool, Ordering};

const BUFFER_ALIGNMENT: usize = 4096;

pub struct QueueBuffers {
    slots: Vec<BufferSlot>,
    queue_count: usize,
    queue_depth: usize,
    buf_len: usize,
}

impl QueueBuffers {
    pub fn new(queue_count: u16, queue_depth: u16, buf_len: usize) -> Result<Self> {
        ensure!(buf_len > 0, "buffer length must be positive");
        let queue_count = queue_count as usize;
        let queue_depth = queue_depth as usize;
        let total = queue_count
            .checked_mul(queue_depth)
            .context("buffer slot count overflow")?;
        let mut slots = Vec::with_capacity(total);
        for _ in 0..total {
            slots.push(BufferSlot::new(buf_len)?);
        }
        Ok(Self {
            slots,
            queue_count,
            queue_depth,
            buf_len,
        })
    }

    pub fn buffer_len(&self) -> usize {
        self.buf_len
    }

    pub fn raw_ptrs(&self) -> Vec<u64> {
        self.slots.iter().map(|slot| slot.ptr() as u64).collect()
    }

    pub fn checkout(&self, queue_id: u16, tag: u16) -> Result<BufferGuard<'_>> {
        let idx = self.index(queue_id, tag)?;
        self.slots[idx].checkout()
    }

    fn index(&self, queue_id: u16, tag: u16) -> Result<usize> {
        let queue = queue_id as usize;
        let tag = tag as usize;
        ensure!(queue < self.queue_count, "queue id out of range");
        ensure!(tag < self.queue_depth, "tag out of range");
        Ok(queue * self.queue_depth + tag)
    }
}

struct BufferSlot {
    buffer: UnsafeCell<AlignedBuffer>,
    checked_out: AtomicBool,
}

unsafe impl Sync for BufferSlot {}

impl BufferSlot {
    fn new(len: usize) -> Result<Self> {
        Ok(Self {
            buffer: UnsafeCell::new(AlignedBuffer::new(len)?),
            checked_out: AtomicBool::new(false),
        })
    }

    fn ptr(&self) -> *mut u8 {
        unsafe { (*self.buffer.get()).as_mut_ptr() }
    }

    fn checkout(&self) -> Result<BufferGuard<'_>> {
        if self
            .checked_out
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(anyhow!("buffer slot checked out twice"));
        }
        Ok(BufferGuard { slot: self })
    }
}

pub struct BufferGuard<'a> {
    slot: &'a BufferSlot,
}

impl<'a> BufferGuard<'a> {
    pub fn as_slice(&self) -> &[u8] {
        unsafe { (*self.slot.buffer.get()).as_slice() }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { (*self.slot.buffer.get()).as_mut_slice() }
    }

    pub fn len(&self) -> usize {
        unsafe { (*self.slot.buffer.get()).len() }
    }

    pub fn ptr(&self) -> *mut u8 {
        self.slot.ptr()
    }
}

impl<'a> Drop for BufferGuard<'a> {
    fn drop(&mut self) {
        self.slot.checked_out.store(false, Ordering::Release);
    }
}

struct AlignedBuffer {
    ptr: NonNull<u8>,
    len: usize,
}

unsafe impl Send for AlignedBuffer {}
unsafe impl Sync for AlignedBuffer {}

impl AlignedBuffer {
    fn new(len: usize) -> Result<Self> {
        ensure!(
            BUFFER_ALIGNMENT <= page_size(),
            "buffer alignment exceeds page size"
        );
        // Anonymous mmap gives us zero-filled memory without eagerly touching
        // every page during device setup.
        let raw = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(io::Error::last_os_error()).context("allocate buffer");
        }
        let ptr = NonNull::new(raw.cast::<u8>()).context("mmap returned null")?;
        Ok(Self { ptr, len })
    }

    fn as_mut_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    fn len(&self) -> usize {
        self.len
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        unsafe {
            let _ = libc::munmap(self.ptr.as_ptr().cast(), self.len);
        }
    }
}

fn page_size() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}
