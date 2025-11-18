# smoo-gadget-buffers

This crate provides a simple `BufferPool` abstraction, which is used to manage allocation and ownership semantics of
the buffers that are handed to ublk.

The basic `VecBufferPool` works exactly like you'd expect.

`DmaEndpointPool` provides dma-buf scratch buffers that stay attached to a single FunctionFS endpoint,
making it easy to DMA payloads to/from USB without sharing those buffers with ublk.
