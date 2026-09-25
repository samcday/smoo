#!/bin/sh

command -v getarg > /dev/null || . /lib/dracut-lib.sh
. /usr/libexec/smoo/smoo-lib

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

getargbool 0 rd.smoo || exit 0

mkdir -p /run/smoo

for mod in configfs libcomposite usb_f_fs ublk_drv; do
    modprobe -q "$mod" 2> /dev/null || :
done

# Checked via /proc/mounts rather than mountpoint(1), which the initrd need
# not carry.
mkdir -p /sys/kernel/config
if ! grep -qs ' /sys/kernel/config ' /proc/mounts; then
    mount -t configfs configfs /sys/kernel/config
fi

# A state file here belongs to an earlier instance that died: its ublk
# devices went with it, so there is nothing to adopt and a fresh start is
# the only useful restart. (The initrd has no other starter for the gadget.)
state_file=$(getarg rd.smoo.state_file=) || state_file=$SMOO_STATE_FILE
rm -f "$state_file"

udc_timeout=$(getarg rd.smoo.udc_timeout=) || udc_timeout=
udc_timeout=$(smoo_parse_seconds "$udc_timeout" 15) \
    || die "smoo: rd.smoo.udc_timeout=$udc_timeout is not a number of seconds"
requested_udc=$(getarg rd.smoo.udc=) || requested_udc=
udc_waited=0
until smoo_pick_udc "$requested_udc" > /dev/null; do
    if [ "$udc_waited" -ge "$udc_timeout" ]; then
        die "smoo: no USB device controller${requested_udc:+ named $requested_udc} appeared after ${udc_timeout}s"
    fi
    sleep 1
    udc_waited=$((udc_waited + 1))
done

# The initrd owns the gadget; smoo-gadget only serves its FunctionFS instance
# (--ffs-dir) and so never creates, rebinds or deletes configfs state. That
# keeps the gadget in place for as long as the root is served, and lets a USB
# manager on the served root (usb-signaller) adopt it and add its own functions
# next to ffs.smoo. The UDC is bound by smoo-gadget-bind (ExecStartPost) once
# smoo-gadget has written its descriptors; never here, where binding would fail
# with ENODEV.
vendor=$(smoo_vendor) || die "smoo: ${vendor#error: }"
product=$(smoo_product) || die "smoo: ${product#error: }"
serial=$(smoo_gadget_serial) || die "smoo: ${serial#error: }"
extra_functions=$(smoo_extra_functions) || {
    warn "smoo: ${extra_functions#error: }; pre-composing no extra functions"
    extra_functions=
}

# A restart of this unit in the initrd finds the gadget, and the FunctionFS
# mount below, still in place: smoo-gadget no longer removes them on exit. A
# gadget an earlier start finished is reused; one whose build failed part way
# is removed and built again (smoo_ensure_gadget).
smoo_ensure_gadget "$vendor" "$product" "$serial" "$extra_functions" \
    || die "smoo: could not build the USB gadget at $SMOO_GADGET_DIR"

mkdir -p "$SMOO_FFS_DIR"
if ! grep -qs " $SMOO_FFS_DIR functionfs " /proc/mounts; then
    # No options: the same mount smoo-gadget made for itself.
    mount -t functionfs "$SMOO_FFS_INSTANCE" "$SMOO_FFS_DIR" \
        || die "smoo: could not mount FunctionFS instance $SMOO_FFS_INSTANCE at $SMOO_FFS_DIR"
fi

# Tell usb-signaller, if the served root runs it, that this gadget carries the
# root: adopt it in place and never unlink ffs.smoo. The temporary name does
# not end in .toml, so a reader never parses a half-written file. Losing this
# file costs the developer link, not the root, as long as usb-signaller is set
# to preserve gadgets it was not told about.
dropin_dir=$SMOO_USB_SIGNALLER_DROPIN_DIR
if mkdir -p "$dropin_dir" \
    && smoo_usb_signaller_dropin > "$dropin_dir/.50-smoo.toml.tmp" \
    && mv -f "$dropin_dir/.50-smoo.toml.tmp" "$dropin_dir/50-smoo.toml"; then
    :
else
    warn "smoo: could not write $dropin_dir/50-smoo.toml; usb-signaller will not adopt the gadget"
fi

log_level=$(getarg rd.smoo.log=)
if [ -n "$log_level" ]; then
    RUST_LOG=$log_level
    export RUST_LOG
fi

ln -sf /usr/bin/smoo-gadget /run/@smoo-gadget
printf '%s\n' "$$" > /run/smoo/smoo-gadget.pid

# Arguments come from smoo_gadget_args so tests can assert on them without a
# device. They go through a file rather than a pipe: a pipe would put the
# "set --" loop in a subshell, where the arguments would be lost. The file
# also shows exactly what the gadget was started with when a run is debugged.
smoo_gadget_args > /run/smoo/gadget-args
set --
while IFS= read -r arg; do
    [ -n "$arg" ] || continue
    set -- "$@" "$arg"
done < /run/smoo/gadget-args

info "smoo: starting initrd root storage daemon"
PATH=/run:$PATH
export PATH
exec @smoo-gadget "$@"
