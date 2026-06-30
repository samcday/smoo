#!/bin/bash

check() {
    require_binaries smoo-gadget || return 1
    return 255
}

depends() {
    echo systemd rootfs-block initqueue dmsquash-live overlayfs
    return 0
}

installkernel() {
    hostonly='' instmods \
        configfs \
        libcomposite \
        usb_f_fs \
        ublk_drv \
        overlay \
        squashfs \
        erofs \
        loop \
        iso9660
}

install() {
    inst_multiple modprobe mount mountpoint mkdir ln rm sleep
    inst /usr/bin/smoo-gadget /usr/bin/smoo-gadget

    inst_hook cmdline 20 "$moddir/parse-smoo.sh"
    inst_hook shutdown 90 "$moddir/smoo-gadget-initrd-stop.sh"
    inst_rules "$moddir/60-smoo-root.rules"

    inst_script "$moddir/smoo-gadget-initrd-start.sh" \
        "/usr/libexec/smoo/smoo-gadget-initrd-start"
    inst_simple "$moddir/smoo-root-storage.service" \
        "$systemdsystemunitdir/smoo-root-storage.service"

    $SYSTEMCTL -q --root "$initdir" add-wants \
        initrd-root-device.target smoo-root-storage.service
}
