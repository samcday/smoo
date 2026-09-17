#!/bin/sh
# Unit tests for the pure helpers in the 90smoo dracut module.
#
# The module's logic normally only runs inside an initrd on a phone. These tests
# stub the dracut library and exercise the helpers directly, so a mistake in
# export selection or the dm-snapshot table is caught on the laptop instead of
# on a device that then fails to boot with no console.
#
# Usage: sh tests/dracut/run.sh

set -u

here=$(dirname "$0")
moddir=$here/../../dracut/modules.d/90smoo

passed=0
failed=0

fail() {
    failed=$((failed + 1))
    printf 'FAIL %s\n' "$*" >&2
}

ok() {
    passed=$((passed + 1))
}

assert_eq() {
    # $1 expected, $2 actual, $3 description
    if [ "$1" = "$2" ]; then
        ok
    else
        fail "$3
  expected: $1
  actual:   $2"
    fi
}

assert_status() {
    # $1 expected status, $2 actual status, $3 description
    if [ "$1" = "$2" ]; then
        ok
    else
        fail "$3: expected status $1, got $2"
    fi
}

# --- dracut library stubs ---------------------------------------------------
# getarg/getargbool read from CMDLINE, which each test sets.

CMDLINE=""

getarg() {
    _want=$1
    for _arg in $CMDLINE; do
        case "$_arg" in
            "$_want"*)
                printf '%s\n' "${_arg#"$_want"}"
                return 0
                ;;
        esac
    done
    return 1
}

getargbool() {
    _default=$1
    _name=$2
    for _arg in $CMDLINE; do
        case "$_arg" in
            "$_name=0") return 1 ;;
            "$_name=1" | "$_name") return 0 ;;
        esac
    done
    [ "$_default" = 1 ]
}

info() { :; }
warn() { :; }
die() {
    printf 'die: %s\n' "$*" >&2
    exit 99
}

# shellcheck source=/dev/null
. "$moddir/smoo-lib.sh"

# --- smoo_gadget_args -------------------------------------------------------

CMDLINE="rd.smoo=1"
args=$(smoo_gadget_args | tr '\n' ' ')
assert_eq "--state-file /run/smoo/state.json --export-map-file /run/smoo/export-map.json " \
    "$args" "default gadget arguments"

CMDLINE="rd.smoo=1 rd.smoo.vendor=0x18d1 rd.smoo.product=0x4ee0 rd.smoo.queue_count=2 rd.smoo.queue_depth=32 rd.smoo.max_io=1048576 rd.smoo.mimic_fastboot=1"
args=$(smoo_gadget_args | tr '\n' ' ')
case "$args" in
    *"--vendor-id 0x18d1"*) ok ;;
    *) fail "vendor id missing from: $args" ;;
esac
case "$args" in
    *"--product-id 0x4ee0"*) ok ;;
    *) fail "product id missing from: $args" ;;
esac
case "$args" in
    *"--queue-count 2"*) ok ;;
    *) fail "queue count missing from: $args" ;;
esac
case "$args" in
    *"--queue-depth 32"*) ok ;;
    *) fail "queue depth missing from: $args" ;;
esac
case "$args" in
    *"--max-io 1048576"*) ok ;;
    *) fail "max io missing from: $args" ;;
esac
case "$args" in
    *--mimic-fastboot*) ok ;;
    *) fail "mimic fastboot missing from: $args" ;;
esac

CMDLINE="rd.smoo=1"
args=$(smoo_gadget_args | tr '\n' ' ')
case "$args" in
    *--mimic-fastboot*) fail "mimic fastboot must be opt-in: $args" ;;
    *) ok ;;
esac

# --- smoo_export_records ----------------------------------------------------

empty_map='{"version":1,"session_id":7,"exports":[]}'
one_map='{"version":1,"session_id":7,"exports":[{"export_id":2863311530,"block_size":512,"size_bytes":4294967296,"assigned_dev_id":0,"devnode":"/dev/ublkb0"}]}'
pending_map='{"version":1,"session_id":7,"exports":[{"export_id":42,"block_size":512,"size_bytes":1024,"assigned_dev_id":null,"devnode":null}]}'
three_map='{"version":1,"session_id":7,"exports":[{"export_id":1,"block_size":512,"size_bytes":1,"assigned_dev_id":0,"devnode":"/dev/ublkb0"},{"export_id":2,"block_size":512,"size_bytes":2,"assigned_dev_id":1,"devnode":"/dev/ublkb1"},{"export_id":3,"block_size":512,"size_bytes":3,"assigned_dev_id":null,"devnode":null}]}'

assert_eq "" "$(printf '%s' "$empty_map" | smoo_export_records)" "empty export map"
assert_eq "2863311530 /dev/ublkb0" "$(printf '%s' "$one_map" | smoo_export_records)" \
    "one ready export"
assert_eq "42 -" "$(printf '%s' "$pending_map" | smoo_export_records)" \
    "an export with no devnode yet is not ready"
assert_eq "1 /dev/ublkb0
2 /dev/ublkb1
3 -" "$(printf '%s' "$three_map" | smoo_export_records)" "three exports"

# --- smoo_select_export -----------------------------------------------------

one_records=$(printf '%s' "$one_map" | smoo_export_records)
three_records=$(printf '%s' "$three_map" | smoo_export_records)
pending_records=$(printf '%s' "$pending_map" | smoo_export_records)

assert_eq "/dev/ublkb0" "$(smoo_select_export "" "$one_records")" \
    "a single ready export is chosen without an explicit id"

assert_eq "/dev/ublkb1" "$(smoo_select_export 2 "$three_records")" \
    "an explicit export id selects that export"

smoo_select_export "" "$three_records" > /dev/null 2>&1
assert_status 2 $? "several ready exports without rd.smoo.root is unsatisfiable"

smoo_select_export "" "$pending_records" > /dev/null 2>&1
assert_status 1 $? "an export that is not ready yet means keep waiting"

smoo_select_export 42 "$pending_records" > /dev/null 2>&1
assert_status 1 $? "a requested export that is not ready yet means keep waiting"

smoo_select_export 99 "$three_records" > /dev/null 2>&1
assert_status 1 $? "a requested export that is absent means keep waiting for it"

smoo_select_export "" "" > /dev/null 2>&1
assert_status 1 $? "an empty map means keep waiting"

# The reason a boot failed has to survive the caller's command substitution,
# which is a subshell, so it travels on stdout rather than in a variable.
out=$(smoo_select_export "" "$three_records" 2>/dev/null) || true
case "$out" in
    "error: rd.smoo.root= is required: 2 exports are ready:"*) ok ;;
    *) fail "ambiguous selection did not explain itself: $out" ;;
esac

out=$(smoo_select_export 99 "$three_records" 2>/dev/null) || true
case "$out" in
    "error: requested export 99 is not in the map;"*) ok ;;
    *) fail "absent export did not explain itself: $out" ;;
esac

# --- smoo_parse_size --------------------------------------------------------

assert_eq "1073741824" "$(smoo_parse_size 1G)" "1G in bytes"
assert_eq "536870912" "$(smoo_parse_size 512M)" "512M in bytes"
assert_eq "2048" "$(smoo_parse_size 2K)" "2K in bytes"
assert_eq "4096" "$(smoo_parse_size 4096)" "a plain byte count"
assert_eq "1073741824" "$(smoo_parse_size 1g)" "a lowercase suffix"

smoo_parse_size "1T" > /dev/null 2>&1
assert_status 1 $? "an unsupported suffix is rejected"
smoo_parse_size "banana" > /dev/null 2>&1
assert_status 1 $? "a non-numeric size is rejected"
smoo_parse_size "" > /dev/null 2>&1
assert_status 1 $? "an empty size is rejected"

# --- smoo_dm_table ----------------------------------------------------------

assert_eq "0 8388608 snapshot /dev/ublkb0 /dev/loop0 N 8" \
    "$(smoo_dm_table 8388608 /dev/ublkb0 /dev/loop0)" "dm-snapshot table"

# --- shell syntax -----------------------------------------------------------

for script in "$moddir"/*.sh; do
    if sh -n "$script"; then
        ok
    else
        fail "sh -n $script"
    fi
done

# ----------------------------------------------------------------------------

printf 'passed %s / failed %s\n' "$passed" "$failed"
[ "$failed" -eq 0 ]
