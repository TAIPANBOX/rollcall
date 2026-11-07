#!/bin/sh
# gate-upgrade.sh -- what a router is left with when apk replaces a version of rollcall.
#
# Invariant: apk runs post-upgrade, not post-install, when it replaces a version, and after that
# run the new daemon is what runs on an enabled router, with the account, the state directory, the
# firewall rules and the snapshot in place; a router whose owner disabled the service is left with
# it disabled and stopped, its rules current; and the configuration and the state are untouched.
#
# It runs the real packages through OpenWrt's own apk, in OpenWrt's root file system. Only a
# different version makes apk replace rather than reinstall, so it takes two: the same tree at two
# package revisions, and it replaces one with the other back and forth. There is no procd in the
# container, so a stand-in for /etc/rc.common writes down what each init script was told and hands
# it to the real one: `restart` really runs start_service as far as procd, which is what brings
# the rules in line and writes the snapshot, and its call to ubus fails harmlessly.
#
# Every check runs even after one has failed, so the output of a run against a package without the
# script is the whole list of what such a package loses.
#
#   PKGREL=2 OUTDIR=dist/upgrade ./scripts/mkapk.sh <rollcalld> <rollcall> <version> x86_64
#   ./scripts/gate-upgrade.sh <apk at r1> <apk at r2>
set -eu

CHECKS='check_install_enables_and_does_not_start check_upgrade_restarts_an_enabled_service check_upgrade_brings_the_rules_in_line check_upgrade_writes_the_snapshot check_upgrade_makes_the_account check_upgrade_repairs_the_state_directory check_upgrade_leaves_a_disabled_service_off check_upgrade_keeps_the_rules_of_a_disabled_service check_upgrade_keeps_config_and_state'

if [ "${1:-}" = "--selftest" ]; then
	n=0; for c in $CHECKS; do echo "$c"; n=$((n + 1)); done
	[ "$n" -gt 0 ] || { echo "measured nothing" >&2; exit 1; }
	exit 0
fi

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OLD=${1:-}
NEW=${2:-}
[ -f "$OLD" ] && [ -f "$NEW" ] || { echo "FAIL: measured nothing: usage: gate-upgrade.sh <apk> <next apk>"; exit 1; }
OLD=$(cd "$(dirname "$OLD")" && pwd)/$(basename "$OLD")
NEW=$(cd "$(dirname "$NEW")" && pwd)/$(basename "$NEW")
# The root file system of gate-feed.sh, pinned by digest. Bump them together.
IMAGE=${ROOTFS_IMAGE:-openwrt/rootfs:x86-64-25.12.6@sha256:14401c04218c2e0da0448f099710ada2460636a92395f353351cc616cf3f67af}
PLATFORM=${PLATFORM:-linux/amd64}
echo "rootfs: $IMAGE"

docker run --rm -i --platform "$PLATFORM" \
	-v "$ROOT/scripts/apk-retry.sh:/apk-retry.sh:ro" \
	-v "$OLD:/one.apk:ro" -v "$NEW:/two.apk:ro" \
	"$IMAGE" /bin/sh -s <<'CONTAINER'
. /apk-retry.sh
set -u
rc=0
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1: $2"; rc=1; }
told() { grep -qx "$1" /tmp/rc-actions; }

mkdir -p /var/lock /var/run /var/state

# What the first boot of a router would have left, so the rule builder and the snapshot have
# something to read.
cat > /etc/config/firewall <<'EOF_FW'
config defaults
	option input 'REJECT'

config zone
	option name 'lan'
	list network 'lan'
	option input 'ACCEPT'

config zone
	option name 'wan'
	list network 'wan'
	option masq '1'
EOF_FW
cat > /etc/config/network <<'EOF_NET'
config interface 'lan'
	option device 'br-lan'
	option proto 'static'

config interface 'wan'
	option device 'eth1'
	option proto 'dhcp'
EOF_NET
cat > /etc/config/system <<'EOF_SYS'
config system
	option hostname 'gate'
	option zonename 'UTC'
EOF_SYS

cp /etc/rc.common /etc/rc.common.real
cat > /etc/rc.common <<'EOF_RC'
#!/bin/sh
case "$1" in */rollcall) echo "$2" >>/tmp/rc-actions ;; esac
exec /bin/sh /etc/rc.common.real "$@"
EOF_RC
: > /tmp/rc-actions

apk update >/tmp/update.log 2>&1 || { cat /tmp/update.log; echo "FAIL: measured nothing: apk update failed"; exit 1; }
apk add --allow-untrusted /one.apk >/tmp/install.log 2>&1 || { cat /tmp/install.log; echo "FAIL: measured nothing: the install failed"; exit 1; }
installed=/one.apk

rule() { uci -q get firewall.rollcall_1.name >/dev/null; }
account() { grep -q '^rollcall:x:1660:1660:' /etc/passwd && grep -q '^rollcall:x:1660:' /etc/group; }

# replace swaps the installed revision for the other one and shows what apk said. It stops the run:
# a replacement that fails measures nothing that follows.
replace() {
	: > /tmp/rc-actions
	if [ "$installed" = /one.apk ]; then installed=/two.apk; else installed=/one.apk; fi
	apk add --allow-untrusted "$installed" >/tmp/replace.log 2>&1 || {
		cat /tmp/replace.log; echo "FAIL: measured nothing: apk refused to replace the package"; exit 1; }
	grep -E 'Executing|Upgrading|Downgrading' /tmp/replace.log | sed 's/^/  apk: /'
	echo "  the init script was told: $(tr '\n' ' ' </tmp/rc-actions)"
}

# ---- an install
if told enable && [ -e /etc/rc.d/S95rollcall ] && ! told restart && ! told start && account && rule; then
	pass check_install_enables_and_does_not_start
else
	fail check_install_enables_and_does_not_start "told: $(tr '\n' ' ' </tmp/rc-actions)"
fi

# ---- an enabled service: the rules gone and no snapshot, as a change of version could leave them
uci -q delete firewall.rollcall_1; uci commit firewall
rm -f /var/run/rollcall/snapshot.json
replace
if told restart && ! told enable; then
	pass check_upgrade_restarts_an_enabled_service
else
	fail check_upgrade_restarts_an_enabled_service "the old daemon goes on running the old binary"
fi
if rule; then pass check_upgrade_brings_the_rules_in_line; else fail check_upgrade_brings_the_rules_in_line "no firewall rule after the replacement"; fi
if [ -s /var/run/rollcall/snapshot.json ]; then pass check_upgrade_writes_the_snapshot; else fail check_upgrade_writes_the_snapshot "no snapshot after the replacement"; fi

# ---- the account gone: procd then runs the daemon with no user set, without a word
sed -i '/^rollcall:/d' /etc/passwd /etc/group /etc/shadow
replace
if account; then pass check_upgrade_makes_the_account; else fail check_upgrade_makes_the_account "no rollcall account after the replacement"; fi

# ---- the state directory changed
account || { echo 'rollcall:x:1660:' >>/etc/group; echo 'rollcall:x:1660:1660:rollcall:/var/empty:/bin/false' >>/etc/passwd; }
chown 0:0 /etc/rollcall
chmod 0755 /etc/rollcall
replace
perm=$(ls -ldn /etc/rollcall | awk '{ print $1, $3, $4 }')
if [ "$perm" = "drwx------ 1660 1660" ]; then pass check_upgrade_repairs_the_state_directory; else fail check_upgrade_repairs_the_state_directory "/etc/rollcall is $perm"; fi

# ---- the owner switched the service off
rm -f /etc/rc.d/S95rollcall
uci -q delete firewall.rollcall_1; uci commit firewall
replace
if [ ! -e /etc/rc.d/S95rollcall ] && ! told enable && ! told restart && ! told start; then
	pass check_upgrade_leaves_a_disabled_service_off
else
	fail check_upgrade_leaves_a_disabled_service_off "told: $(tr '\n' ' ' </tmp/rc-actions)"
fi
if rule; then pass check_upgrade_keeps_the_rules_of_a_disabled_service; else fail check_upgrade_keeps_the_rules_of_a_disabled_service "no firewall rule after the replacement"; fi

# ---- what the owner has
/etc/init.d/rollcall enable
echo '# gate-upgrade marker' >> /etc/config/rollcall
echo marker > /etc/rollcall/marker
replace
if grep -q 'gate-upgrade marker' /etc/config/rollcall && [ -f /etc/rollcall/marker ]; then
	pass check_upgrade_keeps_config_and_state
else
	fail check_upgrade_keeps_config_and_state "the configuration or the state went with the replacement"
fi
exit "$rc"
CONTAINER
echo "gate-upgrade: all checks passed"
