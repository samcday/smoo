#!/bin/sh

command -v getarg > /dev/null || . /lib/dracut-lib.sh

getargbool 0 rd.smoo || return 0

[ -z "$root" ] && root=$(getarg root=)

case "$root" in
    smoo | smoo:*)
        die "smoo: use rd.smoo=1 with root=/dev/smoo-root or root=live:/dev/smoo-root"
        ;;
esac

info "smoo: initrd gadget root storage enabled"
return 0
