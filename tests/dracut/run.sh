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

# A test that needs a value the space-separated CMDLINE cannot carry redefines
# getarg and puts this one back afterwards.
getarg() { cmdline_getarg "$@"; }

cmdline_getarg() {
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
assert_eq "--state-file /run/smoo/state.json --export-map-file /run/smoo/export-map.json --ffs-dir /run/smoo/ffs " \
    "$args" "default gadget arguments"

CMDLINE="rd.smoo=1 rd.smoo.vendor=0x18d1 rd.smoo.product=0x4ee0 rd.smoo.queue_count=2 rd.smoo.queue_depth=32 rd.smoo.max_io=1048576 rd.smoo.mimic_fastboot=1"
args=$(smoo_gadget_args | tr '\n' ' ')
# The initrd owns the gadget: smoo-gadget only serves the FunctionFS instance,
# and the USB ids go into configfs from the start script instead.
case "$args" in
    *"--ffs-dir /run/smoo/ffs "*) ok ;;
    *) fail "--ffs-dir missing from: $args" ;;
esac
case "$args" in
    *--vendor-id* | *--product-id*) fail "USB ids must not reach smoo-gadget: $args" ;;
    *) ok ;;
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

mixed_records=$(printf '%s\n' "1 /dev/ublkb0" "2 -")
smoo_select_export "" "$mixed_records" > /dev/null 2>&1
assert_status 2 $? "one ready plus one pending export is still ambiguous without rd.smoo.root"
assert_eq "/dev/ublkb0" "$(smoo_select_export 1 "$mixed_records")" \
    "an explicit id picks the ready one of a mixed map"

# The reason a boot failed has to survive the caller's command substitution,
# which is a subshell, so it travels on stdout rather than in a variable.
out=$(smoo_select_export "" "$three_records" 2>/dev/null) || true
case "$out" in
    "error: rd.smoo.root= is required: 3 exports present:"*) ok ;;
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

assert_eq "9223372035781033984" "$(smoo_parse_size 8589934591G)" "largest G that fits"
smoo_parse_size 8589934592G > /dev/null 2>&1
assert_status 1 $? "a G value that would wrap is rejected"
assert_eq "9223372036854774784" "$(smoo_parse_size 9007199254740991K)" "largest K that fits"
smoo_parse_size 9007199254740992K > /dev/null 2>&1
assert_status 1 $? "a K value that would wrap is rejected"
smoo_parse_size 8796093022208M > /dev/null 2>&1
assert_status 1 $? "an M value that would wrap is rejected"
smoo_parse_size 9223372036854775808 > /dev/null 2>&1
assert_status 1 $? "a plain count beyond 63 bits is rejected"
assert_eq "9007199254740991" "$(smoo_cow_kib 9223372036854774784)" "the largest COW converts without wrapping"

# --- smoo_parse_seconds -----------------------------------------------------

assert_eq "30" "$(smoo_parse_seconds "" 30)" "empty falls back to the default"
assert_eq "5" "$(smoo_parse_seconds 5 30)" "a plain count is kept"
smoo_parse_seconds banana 30 > /dev/null 2>&1
assert_status 1 $? "a word is not a number of seconds"
smoo_parse_seconds -1 30 > /dev/null 2>&1
assert_status 1 $? "a negative timeout is rejected"
smoo_parse_seconds 9999999999999999999 30 > /dev/null 2>&1
assert_status 1 $? "a timeout beyond the shell's integers is rejected"

smoo_parse_size "1T" > /dev/null 2>&1
assert_status 1 $? "an unsupported suffix is rejected"
smoo_parse_size "banana" > /dev/null 2>&1
assert_status 1 $? "a non-numeric size is rejected"
smoo_parse_size "" > /dev/null 2>&1
assert_status 1 $? "an empty size is rejected"

# --- smoo_dm_table ----------------------------------------------------------

assert_eq "0 8388608 snapshot /dev/ublkb0 /dev/loop0 N 8" \
    "$(smoo_dm_table 8388608 /dev/ublkb0 /dev/loop0)" "dm-snapshot table"

# --- sysfs and udev helpers -------------------------------------------------

SMOO_SYS_BLOCK=$(mktemp -d)
mkdir -p "$SMOO_SYS_BLOCK/ublkb0" "$SMOO_SYS_BLOCK/dm-0/dm" "$SMOO_SYS_BLOCK/dm-1/dm"
printf '16777216\n' > "$SMOO_SYS_BLOCK/ublkb0/size"
printf 'other\n' > "$SMOO_SYS_BLOCK/dm-0/dm/name"
printf 'smoo-root\n' > "$SMOO_SYS_BLOCK/dm-1/dm/name"

assert_eq "16777216" "$(smoo_device_sectors /dev/ublkb0)" "device size comes from sysfs"
smoo_device_sectors /dev/nope > /dev/null 2>&1
assert_status 1 $? "a device without a sysfs entry has no size"
assert_eq 'SUBSYSTEM=="block", KERNEL=="ublkb0", SYMLINK+="smoo-root"' \
    "$(smoo_root_udev_rule /dev/ublkb0)" "udev rule names the kernel device"
assert_eq "dm-1" "$(smoo_dm_kname smoo-root)" "dm kernel name is found by dm name"
smoo_dm_kname missing > /dev/null
assert_status 1 $? "an absent dm device has no kernel name"
assert_eq "2097152" "$(smoo_cow_kib 2147483648)" "2G COW in KiB"
assert_eq "1" "$(smoo_cow_kib 1)" "COW KiB rounds up"
rm -rf "$SMOO_SYS_BLOCK"

# --- gadget identity --------------------------------------------------------

CMDLINE="rd.smoo=1"
assert_eq "0xdead" "$(smoo_vendor)" "default vendor id"
assert_eq "0xbeef" "$(smoo_product)" "default product id"
assert_eq "0001" "$(smoo_gadget_serial)" "default serial matches what smoo-gadget hard-codes"

CMDLINE="rd.smoo=1 rd.smoo.vendor=0x18d1 rd.smoo.product=20192 rd.smoo.serial=TESTSERIAL1"
assert_eq "0x18d1" "$(smoo_vendor)" "vendor id from the command line"
assert_eq "20192" "$(smoo_product)" "decimal product id from the command line"
assert_eq "TESTSERIAL1" "$(smoo_gadget_serial)" "serial from the command line"

CMDLINE="rd.smoo=1 rd.smoo.vendor_id=0x1209 rd.smoo.product_id=0x0001"
assert_eq "0x1209" "$(smoo_vendor)" "rd.smoo.vendor_id is accepted too"
assert_eq "0x0001" "$(smoo_product)" "rd.smoo.product_id is accepted too"

CMDLINE="rd.smoo=1 rd.smoo.serial="
assert_eq "0001" "$(smoo_gadget_serial)" "an empty serial falls back to the default"

for bad in 0x 0x12345 0xgood 65536 banana 0123 -1; do
    CMDLINE="rd.smoo=1 rd.smoo.vendor=$bad"
    smoo_vendor > /dev/null
    assert_status 1 $? "vendor id $bad is rejected"
done
CMDLINE="rd.smoo=1 rd.smoo.product=0x1ffff"
out=$(smoo_product) && fail "an oversized product id was accepted"
case "$out" in
    "error: rd.smoo.product=0x1ffff is not a 16-bit USB id") ok ;;
    *) fail "oversized product id did not explain itself: $out" ;;
esac
smoo_usb_id_ok 0
assert_status 0 $? "0 is a valid USB id"
smoo_usb_id_ok 65535
assert_status 0 $? "65535 is a valid USB id"
smoo_usb_id_ok 0XFFFF
assert_status 0 $? "0XFFFF is a valid USB id"

long_serial=$(printf '%0127d' 0)
CMDLINE="rd.smoo=1 rd.smoo.serial=$long_serial"
smoo_gadget_serial > /dev/null
assert_status 1 $? "a serial longer than a USB string descriptor holds is rejected"

# --- smoo_extra_functions ---------------------------------------------------

CMDLINE="rd.smoo=1"
assert_eq "" "$(smoo_extra_functions)" "no extra functions by default"
smoo_extra_functions > /dev/null
assert_status 0 $? "no rd.smoo.functions is not an error"

CMDLINE="rd.smoo=1 rd.smoo.functions=ncm.usb0,acm.GS0"
assert_eq "ncm.usb0
acm.GS0" "$(smoo_extra_functions)" "a comma list becomes one function per line, in order"

CMDLINE="rd.smoo=1 rd.smoo.functions=ncm.usb0,,ncm.usb0,mass_storage.0,"
assert_eq "ncm.usb0
mass_storage.0" "$(smoo_extra_functions)" "empty entries and duplicates are dropped"

CMDLINE="rd.smoo=1 rd.smoo.functions=ncm.usb0,ffs.x"
out=$(smoo_extra_functions)
assert_status 1 $? "a FunctionFS function is rejected"
case "$out" in
    'error: rd.smoo.functions: "ffs.x" is a FunctionFS function'*) ok ;;
    *) fail "ffs.x rejection did not explain itself: $out" ;;
esac

# Values with whitespace cannot come through the space-separated test command
# line, so these go through a getarg that answers rd.smoo.functions= from
# $bad_value, and the command-line stub is put back afterwards.
getarg() {
    [ "$1" = rd.smoo.functions= ] || return 1
    printf '%s\n' "$bad_value"
}
for bad_value in a/b ncm/usb0 ../x ncm noinstance. .usb0 'ncm.usb 0' "ncm.usb0	" 'ncm.*' 'n-cm.usb0'; do
    out=$(smoo_extra_functions)
    assert_status 1 $? "rd.smoo.functions=\"$bad_value\" is rejected"
    case "$out" in
        error:*) ok ;;
        *) fail "rd.smoo.functions=\"$bad_value\" printed no error: $out" ;;
    esac
done
getarg() { cmdline_getarg "$@"; }
unset bad_value

CMDLINE="rd.smoo=1 rd.smoo.functions=ncm.usb0,a/b"
assert_eq 'error: rd.smoo.functions: "a/b" may only use letters, digits and _.@:+- (no "/" or whitespace)' \
    "$(smoo_extra_functions)" "a bad entry rejects the whole list, not just itself"

# --- smoo_usb_signaller_dropin ----------------------------------------------

expected_dropin='# Written by smoo'"'"'s dracut module: this boot'"'"'s root filesystem is served over
# ffs.smoo. Masking or deleting this file makes usb-signaller leave the gadget
# alone (no developer link), never delete it, provided foreign_gadgets =
# "preserve" is set.
[gadget.smoo]
# Manage the gadget in place while it stays bound. Absent or false: the gadget
# is declared, so protected, but left untouched.
adopt = true
# Never unlinked or removed, must be ready before any bind, vetoes host role.
pinned_functions = ["ffs.smoo"]
# config = "c.1"                 # only needed with more than one config
# keep_identity = true           # the default when adopt = true
# allowed_modes = ["charging_only", "developer_mode", "tethering_mode"]'
assert_eq "$expected_dropin" "$(smoo_usb_signaller_dropin)" "usb-signaller drop-in content"

# The only non-comment lines are the ones usb-signaller parses; anything else
# under [gadget.*] would make its config Broken (deny_unknown_fields).
assert_eq '[gadget.smoo]
adopt = true
pinned_functions = ["ffs.smoo"]' "$(smoo_usb_signaller_dropin | grep -v '^#')" \
    "usb-signaller drop-in keys"

# --- smoo_ffs_ready and smoo_pick_udc ---------------------------------------

fake=$(mktemp -d)
mkdir -p "$fake/fn" "$fake/ffs" "$fake/udc"

smoo_ffs_ready "$fake/fn" "$fake/ffs"
assert_status 1 $? "no ready attribute and no ep1 is not ready"
: > "$fake/ffs/ep1"
smoo_ffs_ready "$fake/fn" "$fake/ffs"
assert_status 0 $? "without a ready attribute, ep1 existing means ready"
printf '0\n' > "$fake/fn/ready"
smoo_ffs_ready "$fake/fn" "$fake/ffs"
assert_status 1 $? "a ready attribute reading 0 wins over ep1"
printf '1\n' > "$fake/fn/ready"
smoo_ffs_ready "$fake/fn" "$fake/ffs"
assert_status 0 $? "a ready attribute reading 1 is ready"

SMOO_UDC_CLASS=$fake/udc
smoo_pick_udc "" > /dev/null
assert_status 1 $? "no UDC to pick while none is present"
mkdir "$fake/udc/b.usb" "$fake/udc/a600000.usb"
assert_eq "a600000.usb" "$(smoo_pick_udc "")" "the first UDC in glob order is picked"
assert_eq "b.usb" "$(smoo_pick_udc b.usb)" "rd.smoo.udc picks that UDC"
smoo_pick_udc c.usb > /dev/null
assert_status 1 $? "a requested UDC that is absent is not replaced by another"
SMOO_UDC_CLASS=/sys/class/udc
rm -rf "$fake"

# --- smoo_ensure_gadget -----------------------------------------------------
# A temporary directory stands in for configfs. mkdir and rmdir are replaced
# with just enough of its behaviour: making a gadget or a config also makes
# its default groups (marked .default), and rmdir takes attributes and default
# groups with a group but, like configfs, refuses while it still holds a
# symlink or a group somebody made. Anything left in the wrong order fails.

fake=$(mktemp -d)
mkdir -p "$fake/usb_gadget"
SMOO_GADGET_DIR=$fake/usb_gadget/smoo
# Read by smoo_teardown_gadget, which must not find a real FunctionFS mount.
# shellcheck disable=SC2034
SMOO_FFS_DIR=$fake/ffs
gadget=$SMOO_GADGET_DIR

mkdir() {
    for _d in "$@"; do
        command mkdir "$_d" || return 1
        case "${_d#"$fake/usb_gadget/"}" in
            */*/*/*) _defaults= ;;
            */configs/*) _defaults="strings" ;;
            */*) _defaults= ;;
            *)
                _defaults="functions configs strings os_desc"
                : > "$_d/UDC"
                ;;
        esac
        for _g in $_defaults; do
            command mkdir "$_d/$_g" && : > "$_d/$_g/.default"
        done
    done
}

fake_group_busy() {
    find "$1" -mindepth 1 \( -type l -o -type d \
        ! -exec sh -c '[ -e "$1/.default" ]' sh '{}' ';' \) -print | grep -q .
}

rmdir() {
    for _d in "$@"; do
        if [ ! -d "$_d" ] || [ -L "$_d" ] || fake_group_busy "$_d"; then
            printf 'fake rmdir: cannot remove %s\n' "$_d" >&2
            return 1
        fi
        command rm -rf "$_d"
    done
}

modprobe() { :; }

# Failing the ffs.smoo link, the last required step, leaves the same
# half-built gadget a failed start leaves on a device.
ln() { return 1; }
smoo_ensure_gadget 0xdead 0xbeef 0001 "ncm.usb0" 2> /dev/null
assert_status 1 $? "a gadget whose ffs.smoo link fails is not built"
unset -f ln
if [ -d "$gadget/functions/ffs.smoo" ] && [ ! -e "$gadget/configs/c.1/ffs.smoo" ]; then
    ok
else
    fail "the failed build did not leave an incomplete gadget behind"
fi
smoo_gadget_complete
assert_status 1 $? "a gadget without the ffs.smoo link is not complete"

# The restart: the incomplete gadget goes and a complete one takes its place.
# The stale idVendor shows whether the gadget was really built again.
echo 0x1234 > "$gadget/idVendor"
smoo_ensure_gadget 0xdead 0xbeef 0001 "ncm.usb0"
assert_status 0 $? "an incomplete gadget is rebuilt"
smoo_gadget_complete
assert_status 0 $? "the rebuilt gadget is complete"
assert_eq "0xdead" "$(cat "$gadget/idVendor")" "the rebuilt gadget has fresh attributes"
assert_eq "$gadget/functions/ffs.smoo" "$(readlink "$gadget/configs/c.1/ffs.smoo")" \
    "the rebuilt gadget links ffs.smoo into c.1"
assert_eq "$gadget/functions/ncm.usb0" "$(readlink "$gadget/configs/c.1/ncm.usb0")" \
    "the rebuilt gadget pre-composes the extra functions"

# A complete gadget is reused as it is; a rebuild would have lost the marker.
: > "$gadget/functions/ffs.smoo/marker"
smoo_ensure_gadget 0x18d1 0x4ee0 0002 ""
assert_status 0 $? "a complete gadget is accepted"
if [ -e "$gadget/functions/ffs.smoo/marker" ]; then
    ok
else
    fail "a complete gadget was rebuilt instead of reused"
fi
assert_eq "0xdead" "$(cat "$gadget/idVendor")" "a reused gadget keeps its identity"

# Teardown copes with everything the build makes, extra functions included.
smoo_teardown_gadget
assert_status 0 $? "a complete, unbound gadget can be torn down"
if [ -e "$gadget" ]; then
    fail "teardown left the gadget directory behind"
else
    ok
fi

# A bound gadget belongs to whoever bound it, complete or not.
mkdir "$gadget" "$gadget/functions/ffs.smoo"
echo a600000.usb > "$gadget/UDC"
smoo_ensure_gadget 0xdead 0xbeef 0001 ""
assert_status 1 $? "an incomplete but bound gadget is not rebuilt"
assert_eq "a600000.usb" "$(cat "$gadget/UDC")" "an incomplete but bound gadget is left alone"

unset -f mkdir rmdir modprobe fake_group_busy
rm -rf "$fake"

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
