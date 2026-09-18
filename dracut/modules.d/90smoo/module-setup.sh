#!/bin/bash

check() {
    require_binaries smoo-gadget || return 1
    return 255
}

depends() {
    # No dmsquash-live: it ships in the separate dracut-live package and is not
    # present on a stock Fedora 45 install, which would make this whole module
    # silently fail to install. smoo serves a plain filesystem image and layers
    # dm-snapshot over it, so the live stack is not needed.
    echo systemd rootfs-block initqueue dm
    return 0
}

installkernel() {
    hostonly='' instmods \
        configfs \
        libcomposite \
        usb_f_fs \
        ublk_drv \
        dm_mod \
        dm_snapshot \
        brd \
        ext4
}

install() {
    inst_multiple modprobe mount grep mkdir ln rm sleep sed tr udevadm dmsetup
    inst /usr/bin/smoo-gadget /usr/bin/smoo-gadget

    inst_hook cmdline 20 "$moddir/parse-smoo.sh"
    inst_hook shutdown 90 "$moddir/smoo-gadget-initrd-stop.sh"

    inst_script "$moddir/smoo-lib.sh" "/usr/libexec/smoo/smoo-lib"
    inst_script "$moddir/smoo-gadget-initrd-start.sh" \
        "/usr/libexec/smoo/smoo-gadget-initrd-start"
    inst_script "$moddir/smoo-root-setup.sh" \
        "/usr/libexec/smoo/smoo-root-setup"

    inst_simple "$moddir/smoo-root-storage.service" \
        "$systemdsystemunitdir/smoo-root-storage.service"
    inst_simple "$moddir/smoo-root-setup.service" \
        "$systemdsystemunitdir/smoo-root-setup.service"

    $SYSTEMCTL -q --root "$initdir" add-wants \
        initrd-root-device.target smoo-root-storage.service
    $SYSTEMCTL -q --root "$initdir" add-wants \
        initrd-root-device.target smoo-root-setup.service
}
