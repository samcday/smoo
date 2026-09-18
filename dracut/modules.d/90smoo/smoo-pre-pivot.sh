#!/bin/sh
# Runs just before switch-root, with the served root mounted at $NEWROOT.
#
# The gadget keeps running across switch-root (SurviveFinalKillSignal, the
# "@" argv[0]), but the systemd that takes over on the served root has never
# heard of its unit: a deserialised unit whose file cannot be found is stopped,
# and stopping the gadget tears down the very device the root is on. Give the
# new root the unit file, in /etc so it works on an image-based root too. The
# write lands in the copy-on-write layer and is gone on reboot.

command -v getarg > /dev/null || . /lib/dracut-lib.sh

getargbool 0 rd.smoo || return 0

unit_dir="$NEWROOT/etc/systemd/system"
mkdir -p "$unit_dir"
for unit in smoo-root-storage.service smoo-root-setup.service; do
    cp -f "/usr/lib/systemd/system/$unit" "$unit_dir/$unit" \
        || warn "smoo: could not place $unit on the served root; the gadget may be stopped after switch-root"
done

return 0
