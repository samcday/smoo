#!/usr/bin/env bash
set -euxo pipefail

echo "preparing smoo integration VM image"
cat /etc/os-release
uname -a

dnf install -y --setopt=install_weak_deps=False fio fio-engine-libaio wireshark-cli

# The Fedora 43 GA cloud image boots kernel 6.17.1, whose dummy_hcd has a
# use-after-free in its emulated single-request IN FIFO: a concurrent
# usb_ep_queue() can clobber the shared fifo_req while dummy_timer is still
# inside its completion callback. smoo's 28-byte interrupt-IN Requests take
# exactly that fast path, so pipelined scenarios would panic the guest every
# few runs. The fix ("usb: gadget: dummy_hcd: prevent fifo_req reuse during
# giveback") is in the 7.2.y stable series. Pin an updated kernel; this string
# is part of the baked image identity, so bump it deliberately.
smoo_vm_kernel_version=7.2.5-100.fc43
smoo_vm_kernel_release="${smoo_vm_kernel_version}.x86_64"
dnf install -y --setopt=install_weak_deps=False \
    "kernel-${smoo_vm_kernel_version}" \
    "kernel-core-${smoo_vm_kernel_version}" \
    "kernel-modules-${smoo_vm_kernel_version}" \
    "kernel-modules-core-${smoo_vm_kernel_version}"

echo "validating pinned kernel ${smoo_vm_kernel_release}"
test -f "/boot/vmlinuz-${smoo_vm_kernel_release}"
test -d "/usr/lib/modules/${smoo_vm_kernel_release}"
for module in libcomposite usb_f_fs ublk_drv usbmon dummy_hcd; do
    modinfo -k "${smoo_vm_kernel_release}" "$module" >/dev/null
done
grubby --set-default "/boot/vmlinuz-${smoo_vm_kernel_release}"
test "$(grubby --default-kernel)" = "/boot/vmlinuz-${smoo_vm_kernel_release}"

echo "validating kernel modules on the bake kernel"
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

for tool in fio dumpcap tshark editcap; do
    command -v "$tool"
done
fio --enghelp=libaio >/dev/null

# The bake VM is still running the GA kernel; drop it so the image only ships
# the pinned one and stays a few hundred MiB smaller. dnf refuses to remove the
# running kernel unless told otherwise, and the modules this script needed are
# already loaded.
bake_kernel_release="$(uname -r)"
if test "$bake_kernel_release" != "$smoo_vm_kernel_release"; then
    dnf remove -y --setopt=protect_running_kernel=False "kernel-core-${bake_kernel_release}"
    test ! -f "/boot/vmlinuz-${bake_kernel_release}"
fi
test "$(grubby --default-kernel)" = "/boot/vmlinuz-${smoo_vm_kernel_release}"

dnf clean all
rm -rf /var/cache/dnf /var/tmp/dnf-*
rm -rf /var/log/journal/*
rm -f /var/log/*.log /var/log/dnf* /var/log/hawkey.log
rm -rf /root/.ssh
cloud-init clean --logs --machine-id
sync

echo "smoo integration VM image prepared"
