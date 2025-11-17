# smoo-buffers

This crate provides a simple `BufferPool` abstraction, which is used to manage allocation and ownership semantics of
the buffers that are handed to ublk.

The basic `VecBufferPool` works exactly like you'd expect.

The `DmaBufPool` juggles a collection of dma-buf fds + their memory mappings rather than normal virtual mem.
