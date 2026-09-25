# smoo dracut module

The `smoo` dracut module starts `smoo-gadget` inside the initrd so a USB host
can serve the root filesystem as a ublk block device. Install the `smoo-dracut`
package in the target rootfs, then rebuild the initrd explicitly:

```sh
dracut --add smoo --force
```

## How it fits together

1. `smoo-root-storage.service` builds the USB gadget in configfs (see
   [The USB gadget](#the-usb-gadget)), mounts its FunctionFS instance at
   `/run/smoo/ffs`, writes the [usb-signaller drop-in](#handing-the-gadget-over)
   and starts `smoo-gadget --ffs-dir /run/smoo/ffs`, which serves that instance
   and never touches configfs itself. The unit's `ExecStartPost`,
   `smoo-gadget-bind`, binds the gadget to the USB device controller once
   `smoo-gadget` has written its descriptors.
2. The gadget survives switch-root (`SurviveFinalKillSignal=yes`, an
   `@smoo-gadget` argv0) because it is still serving the root filesystem long
   after the real root is mounted. A pre-pivot hook copies the unit files into
   the served root's `/etc/systemd/system`: the systemd that takes over would
   otherwise stop a running unit it cannot load, taking the root device down
   with it. `/run`, and with it the FunctionFS mount and the drop-in, moves to
   the new root with everything mounted below it.
3. The gadget writes `/run/smoo/export-map.json`, naming each export it serves
   and the `/dev/ublkb*` node it landed on.
4. `smoo-root-setup.service` waits for that map, picks the export named by
   `rd.smoo.root=`, and symlinks it to `/dev/smoo-export`. It is ordered after
   `smoo-root-storage.service`, which stays "activating" until the bind step
   has finished, so it only starts once the host can see the gadget.
5. Unless `rd.smoo.cow=0`, it then stacks a dm-snapshot over that export with a
   RAM-backed copy-on-write device and points `/dev/smoo-root` at the snapshot.
   Writes stay in RAM: the served image is never modified, and every boot starts
   from the same clean state.
6. `parse-smoo.sh` forces `root=/dev/smoo-root`, so the initrd mounts the served
   device even when an internal disk carries the same filesystem label.

The dracut shutdown hook stops the gadget daemon after the real root has gone
away. It leaves the configfs gadget alone; the daemon's FunctionFS files
closing is what unbinds it.

## The USB gadget

The initrd, not `smoo-gadget`, owns the gadget, and its names are fixed so that
whatever manages USB on the served root can refer to them:

| Item | Value |
|---|---|
| Gadget | `/sys/kernel/config/usb_gadget/smoo` |
| IDs | `idVendor` `rd.smoo.vendor=` (default `0xdead`), `idProduct` `rd.smoo.product=` (default `0xbeef`), `bcdUSB` `0x0200` |
| Device class | `0xEF`/`0x02`/`0x01` (composite with IADs), right for `ffs.smoo` alone and for NCM or ACM next to it. smoo hosts match the interface class, never the device class, IDs or strings. |
| Strings (0x409) | manufacturer `smoo`, product `smoo gadget`, serialnumber `rd.smoo.serial=` (default `0001`) |
| Config | `configs/c.1`, configuration string `smoo`, `MaxPower` 500 |
| smoo function | `functions/ffs.smoo`, FunctionFS instance `smoo` mounted at `/run/smoo/ffs` with no options, linked into `c.1` first so it is always interface 0 |
| Extra functions | `rd.smoo.functions=`, each linked into `c.1` after `ffs.smoo` |
| UDC | `rd.smoo.udc=`, else the first entry in `/sys/class/udc`, written by `smoo-gadget-bind` once `functions/ffs.smoo/ready` reads `1` (or `/run/smoo/ffs/ep1` exists on kernels before 6.9) |

`rd.smoo.functions=ncm.usb0` pre-composes the network function a USB manager on
the served root would add anyway, so a normal boot enumerates once instead of
twice. Entries are `<driver>.<instance>`; FunctionFS (`ffs.*`) is refused
because nothing in the initrd would serve it and an unserved FunctionFS function
makes every bind fail, and so are `/`, whitespace and other punctuation. A
malformed list pre-composes nothing and is logged. Only drivers whose modules
are in the initrd work: the module ships `usb_f_ncm` and `u_ether`.

When the unit restarts inside the initrd, it finds the gadget and the FunctionFS
mount still in place and reuses them; `smoo-gadget --ffs-dir` never deletes
either.

## Handing the gadget over

On the served root the gadget cannot simply be replaced: a USB function can
only be linked into a config of its own gadget, only while that gadget is
unbound, and FunctionFS instance names are global. A USB manager that wants to
offer networking or a serial console therefore has to adopt this gadget in
place, never drop `ffs.smoo` from it, and rebind it around each change. Each
rebind is one re-enumeration, which the smoo host rides out by reconnecting.

| Party | Owns |
|---|---|
| Creator (this module) | the gadget directory, `ffs.smoo`, its FunctionFS mount and daemon, the initial identity, the `/run` drop-in |
| Manager (usb-signaller, once it has adopted the gadget) | `UDC` writes after the first bind, every function other than `ffs.smoo` (including pre-composed ones such as `ncm.usb0`), the identity only if told not to keep it |
| Neither | removing the gadget; removing, unlinking or unmounting `ffs.smoo`; opening its endpoint files |

On every `rd.smoo` boot the start script writes
`/run/usb-signaller/usb-signaller.toml.d/50-smoo.toml`, through a temporary name
that does not end in `.toml` so no reader sees half a file:

```toml
# Written by smoo's dracut module: this boot's root filesystem is served over
# ffs.smoo. Masking or deleting this file makes usb-signaller leave the gadget
# alone (no developer link), never delete it, provided foreign_gadgets =
# "preserve" is set.
[gadget.smoo]
# Manage the gadget in place while it stays bound. Absent or false: the gadget
# is declared, so protected, but left untouched.
adopt = true
# Never unlinked or removed, must be ready before any bind, vetoes host role.
pinned_functions = ["ffs.smoo"]
# config = "c.1"                 # only needed with more than one config
# keep_identity = true           # the default when adopt = true
# allowed_modes = ["charging_only", "developer_mode", "tethering_mode"]
```

It lives in `/run` because the pin is a fact about this boot, not about the
image: an installed boot of the same image has no smoo gadget to keep. The keys
are the ones proposed for usb-signaller's gadget adoption; a usb-signaller
without that support does not know them. An administrator can mask the file
with a `/dev/null` symlink of the same name in
`/etc/usb-signaller/usb-signaller.toml.d/`, or keep the gadget protected but
unmanaged with an `/etc` drop-in setting `adopt = false`. Nothing may declare
`RuntimeDirectory=usb-signaller`: systemd deletes a unit's runtime directory
when it stops, and this file with it.

Hosts that filter by serial number have to be told the gadget's serial:
fastboop's `--smoo-serial` must equal `rd.smoo.serial=` (`0001` unless set)
once fastboop requires it for supplied initrds. The serial stays the same after
usb-signaller adopts the gadget, as long as it keeps the identity (its default
when adopting).

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
| `rd.smoo.udc=<name>` | first in `/sys/class/udc` | USB device controller to bind the gadget to. |
| `rd.smoo.udc_timeout=<s>` | `15` | How long to wait for a USB device controller, and then again for `smoo-gadget` to make `ffs.smoo` ready. |
| `rd.smoo.vendor=`, `rd.smoo.product=` | `0xdead`, `0xbeef` | USB IDs, `0x` hex or decimal. `rd.smoo.vendor_id=`/`rd.smoo.product_id=` also work. |
| `rd.smoo.serial=<s>` | `0001` | USB serial number (`iSerialNumber`), at most 126 characters. |
| `rd.smoo.functions=<drv>.<inst>,...` | none | Extra functions to link next to `ffs.smoo` before the first bind, e.g. `ncm.usb0`. |
| `rd.smoo.queue_count=`, `rd.smoo.queue_depth=`, `rd.smoo.max_io=` | gadget defaults | ublk tuning. |
| `rd.smoo.mimic_fastboot=1` | off | Use fastboot-style interface subclass/protocol for restrictive WebUSB flows. |
| `rd.smoo.experimental_dma_buf=1`, `rd.smoo.dma_heap=` | off | Experimental DMA-BUF fast path. |
| `rd.smoo.metrics_port=<port>` | off | Expose Prometheus metrics. |
| `rd.smoo.state_file=<path>` | `/run/smoo/state.json` | Gadget recovery state. |
| `rd.smoo.log=<level>` | — | `RUST_LOG` for the gadget. |

A typical liveboot command line:

```text
rd.smoo=1 rd.smoo.root=2863311530 rd.smoo.cow.size=2G rd.smoo.functions=ncm.usb0 console=ttyMSM0,115200n8 earlycon
```

## SELinux

`selinux/smoo.cil` carries the allows the datapath needs: io_uring commands
against the ublk character device, and the relabelling the initrd does before
the real policy loads. The `smoo-dracut` package installs it to
`%{_datadir}/selinux/packages/smoo.cil`; installing it into the policy store is
the consuming image's job, so nothing here runs `semodule`.

## Tests

`sh tests/dracut/run.sh` exercises the module's pure helpers — gadget argument
building, USB identity and `rd.smoo.functions` validation, the usb-signaller
drop-in, readiness and UDC selection, export-map parsing and selection,
copy-on-write size parsing and the dm-snapshot table — against a stubbed dracut
library, and syntax-checks every script. It needs no device and no root.
