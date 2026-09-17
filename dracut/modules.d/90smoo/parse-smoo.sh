#!/bin/sh

command -v getarg > /dev/null || . /lib/dracut-lib.sh

getargbool 0 rd.smoo || return 0

[ -z "$root" ] && root=$(getarg root=)

case "$root" in
    smoo | smoo:*)
        die "smoo: use rd.smoo=1 with rd.smoo.root=<export-id>; root= is set for you"
        ;;
esac

info "smoo: initrd gadget root storage enabled"

getargbool 1 rd.smoo.force_root || return 0

# The served root and the device's internal eMMC root can carry the same
# filesystem label (PocketFed labels both "pfroot"), so leaving the image's own
# root= in place risks silently booting the installed system instead of the one
# being served. Point root= at the device smoo-root-setup creates.
#
# This hook is installed at cmdline priority 20. 77dracut-systemd/parse-root.sh
# parses root= at priority 00 and 74rootfs-block/parse-block.sh consumes it at
# priority 95, so reassigning it here lands before anything acts on it.
rootfstype=$(getarg rd.smoo.rootfstype=) || rootfstype=
rootfstype=${rootfstype:-ext4}

root=/dev/smoo-root
rootok=1
export root rootok rootfstype

# getarg reads /etc/cmdline.d after /proc/cmdline and the later value wins, so
# anything that re-reads the command line later sees the served root too.
mkdir -p /etc/cmdline.d
printf 'root=/dev/smoo-root rootfstype=%s rw\n' "$rootfstype" > /etc/cmdline.d/99-smoo-root.conf

info "smoo: root forced to /dev/smoo-root (rootfstype=$rootfstype)"
return 0
