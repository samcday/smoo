#!/bin/sh
# Bind the initrd gadget to a USB device controller once smoo-gadget can serve
# it. Runs as ExecStartPost of smoo-root-storage.service.
#
# smoo-gadget runs with --ffs-dir, so it no longer binds the gadget itself. A
# FunctionFS function can only be bound after its daemon has written the
# descriptors (the kernel refuses with ENODEV before that), and systemd starts
# this the moment the daemon is forked, so wait for that first. The unit stays
# "activating" until this returns, which holds back smoo-root-setup.service
# (After=smoo-root-storage.service) until the host can actually see the gadget.

command -v getarg > /dev/null || . /lib/dracut-lib.sh
. /usr/libexec/smoo/smoo-lib

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

getargbool 0 rd.smoo || exit 0

gadget=$SMOO_GADGET_DIR
ffs_function=$gadget/functions/ffs.$SMOO_FFS_INSTANCE

timeout=$(getarg rd.smoo.udc_timeout=) || timeout=
if ! timeout=$(smoo_parse_seconds "$timeout" 15); then
    warn "smoo: rd.smoo.udc_timeout=$timeout is not a number of seconds"
    exit 1
fi
requested_udc=$(getarg rd.smoo.udc=) || requested_udc=

# Poll five times a second where sleep takes fractions, so a normal boot does
# not lose most of a second to each wait.
if sleep 0.01 2> /dev/null; then
    tick=0.2
    ticks_per_second=5
else
    tick=1
    ticks_per_second=1
fi
limit=$((timeout * ticks_per_second))

# The start script gives up on the controller after the same timeout, and
# only builds the gadget once it has one; each wait gets the full budget.
waited=0
until udc=$(smoo_pick_udc "$requested_udc"); do
    if [ "$waited" -ge "$limit" ]; then
        warn "smoo: no USB device controller${requested_udc:+ named $requested_udc} appeared after ${timeout}s"
        exit 1
    fi
    sleep "$tick"
    waited=$((waited + 1))
done

waited=0
until smoo_ffs_ready "$ffs_function" "$SMOO_FFS_DIR"; do
    if [ "$waited" -ge "$limit" ]; then
        warn "smoo: ffs.$SMOO_FFS_INSTANCE was not ready ${timeout}s after the controller appeared; smoo-gadget has not written its descriptors"
        exit 1
    fi
    sleep "$tick"
    waited=$((waited + 1))
done

# Already bound: an earlier run of this helper did it before the daemon was
# restarted, or something else owns the binding. Either way it is not ours to
# change.
current=
read -r current < "$gadget/UDC" 2> /dev/null || :
if [ -n "$current" ]; then
    info "smoo: gadget already bound to $current"
    exit 0
fi

# The shell's own error for a refused write (EBUSY, ENODEV) goes to the
# journal and console with the rest of the unit's output.
if echo "$udc" > "$gadget/UDC"; then
    read -r current < "$gadget/UDC" 2> /dev/null || current=
    if [ "$current" = "$udc" ]; then
        info "smoo: gadget bound to $udc"
        exit 0
    fi
fi

# configfs reports every failed bind as EBUSY; the real reason is only in the
# kernel log.
warn "smoo: could not bind the gadget at $gadget to $udc"
dmesg 2> /dev/null | grep 'failed to start' | tail -n 5 | while IFS= read -r line; do
    warn "smoo: $line"
done
exit 1
