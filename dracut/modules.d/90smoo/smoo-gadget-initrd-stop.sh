#!/bin/sh
# Stop the gadget daemon after the real root has gone away.
#
# Only the daemon: smoo-gadget runs with --ffs-dir, so it neither built the
# configfs gadget nor removes it on exit. Its FunctionFS files closing is
# enough for the kernel to unbind the gadget, and the host sees it go.

smoo_gadget_initrd_stop() {
    command -v getarg > /dev/null || . /lib/dracut-lib.sh

    [ -r /run/smoo/smoo-gadget.pid ] || return 0
    read -r pid < /run/smoo/smoo-gadget.pid || return 0
    case "$pid" in
        '' | *[!0-9]*)
            warn "smoo: invalid smoo-gadget pid '$pid'"
            return 0
            ;;
    esac

    kill -0 "$pid" 2> /dev/null || return 0
    info "smoo: stopping initrd root storage daemon pid=$pid"
    kill -TERM "$pid" 2> /dev/null || return 0

    waited=0
    while kill -0 "$pid" 2> /dev/null; do
        if [ "$waited" -ge 10 ]; then
            warn "smoo: smoo-gadget pid=$pid did not exit after SIGTERM; sending SIGKILL"
            kill -KILL "$pid" 2> /dev/null || :
            break
        fi
        sleep 1
        waited=$((waited + 1))
    done

    return 0
}

smoo_gadget_initrd_stop "$@"
