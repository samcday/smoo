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

mkdir -p /sys/kernel/config
if ! mountpoint -q /sys/kernel/config; then
    mount -t configfs configfs /sys/kernel/config
fi

udc_timeout=$(getarg rd.smoo.udc_timeout=)
udc_timeout=${udc_timeout:-15}
udc_waited=0
while :; do
    for udc in /sys/class/udc/*; do
        [ -e "$udc" ] && break 2
    done
    if [ "$udc_waited" -ge "$udc_timeout" ]; then
        die "smoo: no USB device controller appeared after ${udc_timeout}s"
    fi
    sleep 1
    udc_waited=$((udc_waited + 1))
done

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
