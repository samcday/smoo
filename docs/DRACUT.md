# smoo dracut module

The `smoo` dracut module starts `smoo-gadget` inside the initrd so a USB host
can serve the root filesystem as a ublk block device. Install the `smoo-dracut`
package in the target rootfs, then rebuild the initrd explicitly:

```sh
dracut --add smoo --force
```

## How it fits together

1. `smoo-root-storage.service` starts `smoo-gadget` from the initrd. It survives
   switch-root (`SurviveFinalKillSignal=yes`, an `@smoo-gadget` argv0) because it
   is still serving the root filesystem long after the real root is mounted.
2. The gadget writes `/run/smoo/export-map.json`, naming each export it serves
   and the `/dev/ublkb*` node it landed on.
3. `smoo-root-setup.service` waits for that map, picks the export named by
   `rd.smoo.root=`, and symlinks it to `/dev/smoo-export`.
4. Unless `rd.smoo.cow=0`, it then stacks a dm-snapshot over that export with a
   RAM-backed copy-on-write device and points `/dev/smoo-root` at the snapshot.
   Writes stay in RAM: the served image is never modified, and every boot starts
   from the same clean state.
5. `parse-smoo.sh` forces `root=/dev/smoo-root`, so the initrd mounts the served
   device even when an internal disk carries the same filesystem label.

The dracut shutdown hook stops the gadget after the real root has gone away.

## Kernel command line

| Argument | Default | Meaning |
|---|---|---|
| `rd.smoo` | off | Enable the module. Everything below is ignored without it. |
| `rd.smoo.root=<id>` | — | Export id to use as root, decimal or `0x` hex. Optional when exactly one export is served. |
| `rd.smoo.root_timeout=<s>` | `30` | How long to wait for that export to appear. |
| `rd.smoo.cow` | on | Stack a disposable dm-snapshot over the export. `rd.smoo.cow=0` writes straight through to the served image. |
| `rd.smoo.cow.size=<size>` | `1G` | Copy-on-write size, with an optional `K`/`M`/`G` suffix. It is sparse and RAM-backed, so this is a ceiling, not an allocation. |
| `rd.smoo.rootfstype=<fs>` | `ext4` | Filesystem of the served image. |
| `rd.smoo.force_root=0` | — | Leave the image's own `root=` alone. |
| `rd.smoo.udc_timeout=<s>` | `15` | How long to wait for a USB device controller. |
| `rd.smoo.vendor=`, `rd.smoo.product=` | gadget defaults | USB IDs. |
| `rd.smoo.queue_count=`, `rd.smoo.queue_depth=`, `rd.smoo.max_io=` | gadget defaults | ublk tuning. |
| `rd.smoo.mimic_fastboot=1` | off | Use fastboot-style interface subclass/protocol for restrictive WebUSB flows. |
| `rd.smoo.experimental_dma_buf=1`, `rd.smoo.dma_heap=` | off | Experimental DMA-BUF fast path. |
| `rd.smoo.metrics_port=<port>` | off | Expose Prometheus metrics. |
| `rd.smoo.state_file=<path>` | `/run/smoo/state.json` | Gadget recovery state. |
| `rd.smoo.log=<level>` | — | `RUST_LOG` for the gadget. |

A typical liveboot command line:

```text
rd.smoo=1 rd.smoo.root=2863311530 rd.smoo.cow.size=2G console=ttyMSM0,115200n8 earlycon
```

## SELinux

`selinux/smoo.cil` carries the allows the datapath needs: io_uring commands
against the ublk character device, and the relabelling the initrd does before
the real policy loads. The `smoo-dracut` package installs it to
`%{_datadir}/selinux/packages/smoo.cil`; installing it into the policy store is
the consuming image's job, so nothing here runs `semodule`.

## Tests

`sh tests/dracut/run.sh` exercises the module's pure helpers — gadget argument
building, export-map parsing and selection, copy-on-write size parsing and the
dm-snapshot table — against a stubbed dracut library, and syntax-checks every
script. It needs no device and no root.
