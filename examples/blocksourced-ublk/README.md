# blocksourced-ublk

This is a simple example that wires up smoo's ublk implementation to the host `BlockSource` abstraction, for quick
testing and iteration.

Put differently, this distills the extreme ends of smoo's data path (/dev/ublkbN on one end, a backing file/device on
the other) without all the USB gunk in-between (so you can easily run it on one computer).

The `--meow` flag swaps the backing storage for the procedural `smoo-purrfection` FAT volume, letting you expose the
infinite-cats demo through ublk without downloading any images ahead of time.
