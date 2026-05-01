#!/usr/bin/env bash
set -euxo pipefail

echo "preparing smoo integration VM image"
cat /etc/os-release
uname -a

dnf install -y --setopt=install_weak_deps=False fio wireshark-cli

echo "validating kernel modules"
modprobe configfs || true
modprobe libcomposite
modprobe usb_f_fs
modprobe ublk_drv
modprobe usbmon
modprobe dummy_hcd num_instances=4

mountpoint -q /sys/kernel/config || mount -t configfs configfs /sys/kernel/config
mountpoint -q /sys/kernel/debug || mount -t debugfs debugfs /sys/kernel/debug

test -d /sys/kernel/config/usb_gadget
test -e /dev/ublk-control
test -e /sys/class/udc/dummy_udc.0
if ! test -d /sys/kernel/debug/usb/usbmon && ! test -e /dev/usbmon0; then
    echo "usbmon interface missing"
    exit 1
fi

for tool in fio dumpcap tshark; do
    command -v "$tool"
done

dnf clean all
rm -rf /var/cache/dnf /var/tmp/dnf-*
rm -rf /var/log/journal/*
rm -f /var/log/*.log /var/log/dnf* /var/log/hawkey.log
rm -rf /root/.ssh
cloud-init clean --logs --machine-id
sync

echo "smoo integration VM image prepared"
