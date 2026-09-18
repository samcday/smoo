#!/bin/sh
# Resolve the smoo export serving the root filesystem and present it as
# /dev/smoo-root, optionally behind a disposable dm-snapshot.

command -v getarg > /dev/null || . /lib/dracut-lib.sh
. /usr/libexec/smoo/smoo-lib

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

getargbool 0 rd.smoo || exit 0

requested=$(getarg rd.smoo.root=) || requested=
reason=
case "$requested" in
    0x* | 0X*) requested=$(printf '%d' "$requested" 2> /dev/null) || requested= ;;
esac

timeout=$(getarg rd.smoo.root_timeout=) || timeout=
timeout=${timeout:-30}

waited=0
devnode=
while :; do
    if [ -r "$SMOO_EXPORT_MAP" ]; then
        records=$(smoo_export_records < "$SMOO_EXPORT_MAP")
        selected=$(smoo_select_export "$requested" "$records")
        status=$?
        case "$status" in
            0)
                devnode=$selected
                [ -b "$devnode" ] && break
                devnode=
                reason="${selected} is not a block device yet"
                ;;
            2) die "smoo: ${selected#error: }" ;;
            *) reason=${selected#error: } ;;
        esac
    else
        reason="$SMOO_EXPORT_MAP has not appeared"
    fi
    if [ "$waited" -ge "$timeout" ]; then
        die "smoo: no usable export after ${timeout}s: ${reason:-unknown}"
    fi
    sleep 1
    waited=$((waited + 1))
done

info "smoo: serving root from export ${requested:-(only one)} at $devnode"
ln -sf "$devnode" /dev/smoo-export

# Expose $1 (a kernel block device name) as /dev/smoo-root through udev, which
# is the only way systemd learns the root device has arrived.
publish_root() {
    mkdir -p "${SMOO_UDEV_RULE%/*}"
    smoo_root_udev_rule "$1" > "$SMOO_UDEV_RULE"
    udevadm control --reload
    udevadm trigger --settle --action=change --sysname-match="$1"
    waited=0
    while [ ! -e /dev/smoo-root ]; do
        if [ "$waited" -ge 10 ]; then
            die "smoo: udev did not create /dev/smoo-root for $1"
        fi
        sleep 1
        waited=$((waited + 1))
    done
}

if ! getargbool 1 rd.smoo.cow; then
    publish_root "${devnode##*/}"
    info "smoo: copy-on-write disabled, root writes go straight to the served image"
    exit 0
fi

cow_size=$(getarg rd.smoo.cow.size=) || cow_size=
cow_size=${cow_size:-1G}
cow_bytes=$(smoo_parse_size "$cow_size") \
    || die "smoo: rd.smoo.cow.size=$cow_size is not a byte count with an optional K/M/G suffix"

sectors=$(smoo_device_sectors "$devnode") \
    || die "smoo: cannot read the size of $devnode"

# The COW device is a brd RAM disk: it allocates pages only for the chunks that
# get dirtied, vanishes on reboot, and needs no loop device, sparse file or the
# tools that make them, which not every initrd carries.
cow_kib=$(smoo_cow_kib "$cow_bytes")
cow=/dev/ram0
if [ ! -e "$cow" ]; then
    # The insmod fallback covers modules staged outside the module tree, as
    # PocketFed's liveboot injector does.
    modprobe -q brd rd_nr=1 rd_size="$cow_kib" 2> /dev/null \
        || insmod /usr/lib/smoo/modules/brd.ko rd_nr=1 rd_size="$cow_kib" 2> /dev/null \
        || die "smoo: cannot load brd for the copy-on-write device"
fi
waited=0
while [ ! -e "$cow" ]; do
    if [ "$waited" -ge 10 ]; then
        die "smoo: $cow did not appear after loading brd"
    fi
    sleep 1
    waited=$((waited + 1))
done
cow_sectors=$(smoo_device_sectors "$cow") || die "smoo: cannot read the size of $cow"
if [ "$cow_sectors" -lt $((cow_bytes / 512)) ]; then
    die "smoo: $cow holds $cow_sectors sectors, fewer than the $cow_size requested; brd was loaded with a smaller rd_size"
fi

modprobe -q dm_snapshot 2> /dev/null || :
table=$(smoo_dm_table "$sectors" "$devnode" "$cow")
# --noudevsync: without device-mapper udev rules in the initrd nobody would
# complete the udev cookie dmsetup otherwise waits on.
printf '%s\n' "$table" | dmsetup create "$SMOO_DM_NAME" --noudevsync \
    || die "smoo: dmsetup create $SMOO_DM_NAME failed for table: $table"

kname=$(smoo_dm_kname "$SMOO_DM_NAME") \
    || die "smoo: device-mapper device $SMOO_DM_NAME did not appear in sysfs"
publish_root "$kname"
info "smoo: root is a disposable snapshot of $devnode with a ${cow_size} RAM overlay"
