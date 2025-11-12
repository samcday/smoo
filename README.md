# smoo

**smoo** is an *inverted* mass‑storage USB protocol. The device sees a block device whose data comes from the host.

It uses the [ublk][] driver and [FunctionFS][ffs] to implement the device side of the protocol in user-space.  It can
make use of [FunctionFS DMA-BUF support][ffs-dmabuf] for a (nearly) zero-copy data path.

The host implementation supports `rusb` (for CLI and desktop apps) and WebUSB (for WASM + web targets).

It is implemented in async-first Rust, mostly by robots.

"UMS" backwards is "SMU". Which sounds like smoo. So there you go.

## Quickstart

```
# from a computer with a UDC
cargo run --bin=smoo-gadget-cli

# from another computer connected to the one with a UDC
dd if=/dev/urandom of=random.img bs=4096 count=512
cargo run --bin=smoo-host-cli -f random.img

# the UDC computer should now see a /dev/ublk0 that returns data matching random.img
```

## Status

This is an early prototype. It requires a recent Linux kernel with [FunctionFS][ffs], and [ublk][] support enabled. It
should work on any device with a UDC, and is tested primarily on SDM670/SDM845 pocket computers.

## Development

See **HACKING.md** for architecture and implementation details.

[ublk]: https://docs.kernel.org/block/ublk.html
[ffs]: https://docs.kernel.org/usb/functionfs.html
[ffs-dmabuf]: https://docs.kernel.org/usb/functionfs.html#dmabuf-interface
