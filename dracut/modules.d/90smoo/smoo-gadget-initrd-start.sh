#!/bin/sh

command -v getarg > /dev/null || . /lib/dracut-lib.sh

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

state_file=$(getarg rd.smoo.state_file=)
state_file=${state_file:-/run/smoo/state.json}
set -- --state-file "$state_file"

vendor_id=$(getarg rd.smoo.vendor=)
[ -n "$vendor_id" ] || vendor_id=$(getarg rd.smoo.vendor_id=)
[ -n "$vendor_id" ] && set -- "$@" --vendor-id "$vendor_id"

product_id=$(getarg rd.smoo.product=)
[ -n "$product_id" ] || product_id=$(getarg rd.smoo.product_id=)
[ -n "$product_id" ] && set -- "$@" --product-id "$product_id"

queue_count=$(getarg rd.smoo.queue_count=)
[ -n "$queue_count" ] && set -- "$@" --queue-count "$queue_count"

queue_depth=$(getarg rd.smoo.queue_depth=)
[ -n "$queue_depth" ] || queue_depth=$(getarg rd.smoo.queue_size=)
[ -n "$queue_depth" ] && set -- "$@" --queue-depth "$queue_depth"

max_io=$(getarg rd.smoo.max_io_bytes=)
[ -n "$max_io" ] || max_io=$(getarg rd.smoo.max_io=)
[ -n "$max_io" ] && set -- "$@" --max-io "$max_io"

metrics_port=$(getarg rd.smoo.metrics_port=)
[ -n "$metrics_port" ] && set -- "$@" --metrics-port "$metrics_port"

getargbool 0 rd.smoo.experimental_dma_buf && set -- "$@" --experimental-dma-buf

dma_heap=$(getarg rd.smoo.dma_heap=)
[ -n "$dma_heap" ] && set -- "$@" --dma-heap "$dma_heap"

getargbool 0 rd.smoo.mimic_fastboot && set -- "$@" --mimic-fastboot

log_level=$(getarg rd.smoo.log=)
if [ -n "$log_level" ]; then
    RUST_LOG=$log_level
    export RUST_LOG
fi

ln -sf /usr/bin/smoo-gadget /run/@smoo-gadget
printf '%s\n' "$$" > /run/smoo/smoo-gadget.pid

info "smoo: starting initrd root storage daemon"
PATH=/run:$PATH
export PATH
exec @smoo-gadget "$@"
