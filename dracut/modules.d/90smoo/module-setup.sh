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
    inst_hook pre-pivot 50 "$moddir/smoo-pre-pivot.sh"
    inst_hook shutdown 90 "$moddir/smoo-gadget-initrd-stop.sh"

    inst_script "$moddir/smoo-lib.sh" "/usr/libexec/smoo/smoo-lib"
    inst_script "$moddir/smoo-gadget-initrd-start.sh" \
        "/usr/libexec/smoo/smoo-gadget-initrd-start"
    inst_script "$moddir/smoo-root-setup.sh" \
        "/usr/libexec/smoo/smoo-root-setup"

    # Install the /dev/smoo-root naming rule up front so it is active before
    # the dm device exists and does not depend on a runtime `udevadm control
    # --reload` (which fails once dracut has closed the udev control socket).
    inst_simple "$moddir/60-smoo-root.rules" "$udevdir/rules.d/60-smoo-root.rules"

    inst_simple "$moddir/smoo-root-storage.service" \
        "$systemdsystemunitdir/smoo-root-storage.service"
    inst_simple "$moddir/smoo-root-setup.service" \
        "$systemdsystemunitdir/smoo-root-setup.service"

    # inst_script/inst_hook copy the source mode verbatim. The scripts are
    # executable in git, but a checkout or packaging step that drops the mode
    # would make every smoo unit fail with status 203/EXEC ("Permission
    # denied") in the initrd, as the DB410c lane-42 trial did
    # (43-liveboot-v2-db410c-trial/evidence/20-uart-liveboot.log). Make the
    # installed copies executable defensively.
    for _script in \
        "$initdir/usr/libexec/smoo/smoo-lib" \
        "$initdir/usr/libexec/smoo/smoo-gadget-initrd-start" \
        "$initdir/usr/libexec/smoo/smoo-root-setup" \
        "$initdir/usr/lib/dracut/hooks/cmdline/parse-smoo.sh" \
        "$initdir/usr/lib/dracut/hooks/pre-pivot/smoo-pre-pivot.sh" \
        "$initdir/usr/lib/dracut/hooks/shutdown/smoo-gadget-initrd-stop.sh"; do
        [ -e "$_script" ] && chmod 0755 "$_script"
    done

    $SYSTEMCTL -q --root "$initdir" add-wants \
        initrd-root-device.target smoo-root-storage.service
    $SYSTEMCTL -q --root "$initdir" add-wants \
        initrd-root-device.target smoo-root-setup.service
}
