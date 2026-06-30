# smoo dracut module

The `smoo` dracut module starts `smoo-gadget` in the initrd so a USB host can
serve the root filesystem as a ublk block device. Install the `smoo-dracut`
package in the target rootfs, then rebuild the initrd explicitly:

```sh
dracut --add smoo --force
```

Enable the module at boot with `rd.smoo=1`. The module exposes the first smoo
ublk disk as `/dev/smoo-root`.

Fedora LiveOS-style images can use the existing dracut live stack:

```text
rd.smoo=1 root=live:/dev/smoo-root
```

Direct lower filesystem images can use normal block-root syntax. For a writable
overlay on top of a read-only EROFS lower image:

```text
rd.smoo=1 root=/dev/smoo-root rootfstype=erofs rd.overlay
```

Useful optional kernel arguments:

```text
rd.smoo.vendor=0xDEAD
rd.smoo.product=0xBEEF
rd.smoo.queue_count=1
rd.smoo.queue_depth=16
rd.smoo.max_io=1048576
rd.smoo.mimic_fastboot=1
rd.smoo.log=debug
```

The initrd service is a systemd root-storage daemon: it uses
`IgnoreOnIsolate=yes`, `SurviveFinalKillSignal=yes`, and starts `smoo-gadget`
through an `@smoo-gadget` argv0 so the process survives switch-root. It is
stopped later by the dracut shutdown hook after the real root has gone away.
