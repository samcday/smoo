use anyhow::{Context, Result, ensure};

/// Provides temporary byte buffers keyed by ublk queue + tag.
pub trait BufferPool {
    /// Returns the capacity of each buffer in bytes.
    fn buffer_len(&self) -> usize;

    /// Checks out the buffer assigned to `queue_id`/`tag`.
    fn checkout(&mut self, queue_id: u16, tag: u16) -> Result<Vec<u8>>;

    /// Returns the buffer to the pool.
    fn checkin(&mut self, queue_id: u16, tag: u16, buf: Vec<u8>);
}

/// BufferPool backed by a Vec of reusable `Vec<u8>` slots.
pub struct VecBufferPool {
    slots: Vec<Option<Vec<u8>>>,
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
            slots.push(Some(vec![0u8; buf_len]));
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

    fn checkout(&mut self, queue_id: u16, tag: u16) -> Result<Vec<u8>> {
        let idx = self.index(queue_id, tag)?;
        self.slots[idx].take().context("buffer already checked out")
    }

    fn checkin(&mut self, queue_id: u16, tag: u16, mut buf: Vec<u8>) {
        if buf.len() != self.buf_len {
            buf.resize(self.buf_len, 0);
        }
        let idx = self
            .index(queue_id, tag)
            .expect("buffer index out of range");
        let previous = self.slots[idx].replace(buf);
        debug_assert!(previous.is_none(), "buffer slot occupied during checkin");
    }
}
