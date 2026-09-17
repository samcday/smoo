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

if ! getargbool 1 rd.smoo.cow; then
    ln -sf "$devnode" /dev/smoo-root
    info "smoo: copy-on-write disabled, root writes go straight to the served image"
    exit 0
fi

cow_size=$(getarg rd.smoo.cow.size=) || cow_size=
cow_size=${cow_size:-1G}
cow_bytes=$(smoo_parse_size "$cow_size") \
    || die "smoo: rd.smoo.cow.size=$cow_size is not a byte count with an optional K/M/G suffix"

sectors=$(blockdev --getsz "$devnode") \
    || die "smoo: cannot read the size of $devnode"

mkdir -p "${SMOO_COW_IMAGE%/*}"
# /run is a tmpfs, so the COW lives in RAM and is sparse: only dirtied chunks
# ever cost anything, and the whole thing vanishes on reboot.
truncate -s "$cow_bytes" "$SMOO_COW_IMAGE" \
    || die "smoo: cannot create the copy-on-write image at $SMOO_COW_IMAGE"
cow=$(losetup --find --show "$SMOO_COW_IMAGE") \
    || die "smoo: cannot attach a loop device to $SMOO_COW_IMAGE"

modprobe -q dm_snapshot 2> /dev/null || :
table=$(smoo_dm_table "$sectors" "$devnode" "$cow")
printf '%s\n' "$table" | dmsetup create "$SMOO_DM_NAME" \
    || die "smoo: dmsetup create $SMOO_DM_NAME failed for table: $table"

ln -sf "/dev/mapper/$SMOO_DM_NAME" /dev/smoo-root
info "smoo: root is a disposable snapshot of $devnode with a ${cow_size} RAM overlay"
