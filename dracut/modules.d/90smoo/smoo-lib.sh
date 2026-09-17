#!/bin/sh
# Pure helpers for the smoo dracut module.
#
# Everything here is free of side effects so tests/dracut/run.sh can source this
# file with a stubbed dracut library and assert on the results. The scripts that
# touch the system (smoo-gadget-initrd-start.sh, smoo-root-setup.sh) keep only
# the parts that cannot be tested without a device.

SMOO_EXPORT_MAP=${SMOO_EXPORT_MAP:-/run/smoo/export-map.json}
SMOO_STATE_FILE=${SMOO_STATE_FILE:-/run/smoo/state.json}
SMOO_COW_IMAGE=${SMOO_COW_IMAGE:-/run/smoo/cow.img}
SMOO_DM_NAME=${SMOO_DM_NAME:-smoo-root}

# Build the smoo-gadget argument list from the kernel command line.
#
# Echoes one argument per line, because an argument value may legitimately
# contain characters a space-separated string would mangle. Callers read it back
# with the newline IFS trick, not with word splitting.
smoo_gadget_args() {
    printf '%s\n' --state-file "$(getarg rd.smoo.state_file= || printf '%s' "$SMOO_STATE_FILE")"
    printf '%s\n' --export-map-file "$SMOO_EXPORT_MAP"

    _value=$(getarg rd.smoo.vendor=) || _value=$(getarg rd.smoo.vendor_id=) || _value=
    [ -n "$_value" ] && printf '%s\n' --vendor-id "$_value"

    _value=$(getarg rd.smoo.product=) || _value=$(getarg rd.smoo.product_id=) || _value=
    [ -n "$_value" ] && printf '%s\n' --product-id "$_value"

    _value=$(getarg rd.smoo.queue_count=) || _value=
    [ -n "$_value" ] && printf '%s\n' --queue-count "$_value"

    _value=$(getarg rd.smoo.queue_depth=) || _value=$(getarg rd.smoo.queue_size=) || _value=
    [ -n "$_value" ] && printf '%s\n' --queue-depth "$_value"

    _value=$(getarg rd.smoo.max_io_bytes=) || _value=$(getarg rd.smoo.max_io=) || _value=
    [ -n "$_value" ] && printf '%s\n' --max-io "$_value"

    _value=$(getarg rd.smoo.metrics_port=) || _value=
    [ -n "$_value" ] && printf '%s\n' --metrics-port "$_value"

    getargbool 0 rd.smoo.experimental_dma_buf && printf '%s\n' --experimental-dma-buf

    _value=$(getarg rd.smoo.dma_heap=) || _value=
    [ -n "$_value" ] && printf '%s\n' --dma-heap "$_value"

    getargbool 0 rd.smoo.mimic_fastboot && printf '%s\n' --mimic-fastboot

    return 0
}

# Reduce an export map JSON document to "<export_id> <devnode>" lines.
#
# An export whose ublk device is not up yet has a null devnode; it is reported
# with "-" so the caller can tell "not ready" apart from "not present" and wait
# instead of failing. No JSON parser is available in the initrd.
smoo_export_records() {
    tr -d ' \t\n' \
        | sed -e 's/.*"exports":\[//' -e 's/\].*//' -e 's/},{/}\
{/g' \
        | while IFS= read -r _record || [ -n "$_record" ]; do
            # The "|| [ -n ... ]" matters: the last record has no trailing
            # newline, and a plain read would drop it.
            [ -n "$_record" ] || continue
            _id=$(printf '%s' "$_record" | sed -n 's/.*"export_id":\([0-9][0-9]*\).*/\1/p')
            [ -n "$_id" ] || continue
            _dev=$(printf '%s' "$_record" | sed -n 's/.*"devnode":"\([^"]*\)".*/\1/p')
            printf '%s %s\n' "$_id" "${_dev:--}"
        done
}

# Pick the export to use.
#
# $1: requested export id, empty for "there should be exactly one".
# $2: records as produced by smoo_export_records.
#
# Prints the devnode and returns 0. On failure it prints "error: <reason>"
# instead and returns 1 when nothing is ready yet (the caller should keep
# waiting) or 2 when the request can never be satisfied (ambiguous).
#
# The reason goes to stdout rather than a variable because the caller reads this
# through a command substitution, which is a subshell: a variable set here would
# never reach it, and the explanation for a failed boot is exactly what must not
# get lost.
smoo_select_export() {
    _requested=$1
    _records=$2
    _ready_dev=
    _ready_count=0
    _seen=
    _requested_present=0

    _oldifs=$IFS
    IFS='
'
    for _record in $_records; do
        _id=${_record%% *}
        _dev=${_record#* }
        [ -n "$_id" ] || continue
        _seen="$_seen $_id"
        if [ -n "$_requested" ] && [ "$_id" = "$_requested" ]; then
            _requested_present=1
        fi
        [ "$_dev" = "-" ] && continue
        if [ -n "$_requested" ]; then
            if [ "$_id" = "$_requested" ]; then
                IFS=$_oldifs
                printf '%s\n' "$_dev"
                return 0
            fi
        else
            _ready_dev=$_dev
            _ready_count=$((_ready_count + 1))
        fi
    done
    IFS=$_oldifs

    if [ -n "$_requested" ]; then
        # Present but not ready yet is worth waiting for; absent is not, but the
        # map is rewritten as exports appear, so only the caller's timeout can
        # decide that. Report "keep waiting" either way and let it give up.
        [ "$_requested_present" = 1 ] && return 1
        printf 'error: requested export %s is not in the map; saw:%s\n' \
            "$_requested" "${_seen:- none}"
        return 1
    fi

    if [ "$_ready_count" -eq 1 ]; then
        printf '%s\n' "$_ready_dev"
        return 0
    fi
    if [ "$_ready_count" -eq 0 ]; then
        printf 'error: no export is ready yet; saw:%s\n' "${_seen:- none}"
        return 1
    fi
    printf 'error: rd.smoo.root= is required: %s exports are ready:%s\n' \
        "$_ready_count" "$_seen"
    return 2
}

# Convert a byte count with an optional K/M/G suffix to plain bytes.
smoo_parse_size() {
    _value=$1
    [ -n "$_value" ] || return 1
    _number=${_value%[KkMmGg]}
    _suffix=${_value#"$_number"}
    case "$_number" in
        '' | *[!0-9]*) return 1 ;;
    esac
    case "$_suffix" in
        K | k) printf '%s\n' $((_number * 1024)) ;;
        M | m) printf '%s\n' $((_number * 1024 * 1024)) ;;
        G | g) printf '%s\n' $((_number * 1024 * 1024 * 1024)) ;;
        '') printf '%s\n' "$_number" ;;
        *) return 1 ;;
    esac
}

# The dm-snapshot table mapping the whole origin device through a COW device.
#
# "N" keeps the snapshot metadata in RAM: a liveboot root is deliberately
# disposable and must never write back to the served image. 8 sectors is a 4 KiB
# chunk, matching the page and filesystem block size.
smoo_dm_table() {
    printf '0 %s snapshot %s %s N 8\n' "$1" "$2" "$3"
}
