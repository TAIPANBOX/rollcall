#!/bin/sh
# gate-firewall-place.sh -- the rule builder keeps rollcall's firewall rules where they stand, under
# OpenWrt's own uci.
#
# Invariant (I13h): a start of the service, and so every firewall reload, leaves a rule that already
# holds what the configuration needs exactly where it is in /etc/config/firewall and writes
# nothing; a rule that differs is rewritten in its place. uci adds a new section at the end of the
# file, so the delete and add of earlier versions moved rollcall_1 below every section written
# after it (Flint 2 on OpenWrt 25.12.6, 2026-11-12: below the include hermes_net, and the nightly
# drift check of the lab routers reported a change nobody made). TestFirewallRuleKeepsItsPlace
# holds the same against a stub; this runs the builder against the real uci of OpenWrt's root file
# system, so the stub's idea of where uci puts a section is checked too.
#
# Every check runs even after one has failed.
#
#   ./scripts/gate-firewall-place.sh [init script]     default: packaging/files/etc/init.d/rollcall
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
INIT=${1:-$ROOT/packaging/files/etc/init.d/rollcall}
[ -f "$INIT" ] || { echo "FAIL: measured nothing: no init script at $INIT"; exit 1; }
INIT=$(cd "$(dirname "$INIT")" && pwd)/$(basename "$INIT")
# The root file system of gate-feed.sh and gate-upgrade.sh, pinned by digest. Bump them together.
IMAGE=${ROOTFS_IMAGE:-openwrt/rootfs:x86-64-25.12.6@sha256:14401c04218c2e0da0448f099710ada2460636a92395f353351cc616cf3f67af}
PLATFORM=${PLATFORM:-linux/amd64}
echo "rootfs: $IMAGE"

docker run --rm -i --platform "$PLATFORM" -v "$INIT:/rollcall.init:ro" "$IMAGE" /bin/sh -s <<'CONTAINER'
rc=0
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1: $2"; rc=1; }
mkdir -p /var/lock /var/run

cat > /etc/config/firewall <<'EOF_FW'
config defaults
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'REJECT'

config zone
	option name 'lan'
	list network 'lan'
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'ACCEPT'

config zone
	option name 'wan'
	list network 'wan'
	list network 'wan6'
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'REJECT'
	option masq '1'

config forwarding
	option src 'lan'
	option dest 'wan'
EOF_FW
cat > /etc/config/rollcall <<'EOF_RC'
config rollcall 'main'
	list peer_zone 'lan'
	list peer_zone 'wan'
	list peer '192.0.2.10'
	option port '7432'
EOF_RC

# The builder, as uci-defaults, postinst and every start run it.
. /rollcall.init
build() { firewall 2>/tmp/build.err; }
# The named sections of the firewall, in the order of the file (uci show writes the others as @type[n]).
order() { uci show firewall | sed -n 's/^firewall\.\([A-Za-z0-9_]*\)=.*/\1/p' | tr '\n' ' '; }

# The first build, then another package adds a section of its own below the rules, as
# hermes-openwrt does.
build
uci set firewall.hermes_net=include
uci set firewall.hermes_net.type=script
uci set firewall.hermes_net.path=/usr/libexec/hermes-net-reapply
uci set firewall.hermes_net.enabled=1
uci commit firewall
case $(order) in
*'rollcall_1 rollcall_2 hermes_net '*) ;;
*)
	echo "FAIL: measured nothing: the rules are not above the later section after the first build: $(order)"
	cat /tmp/build.err
	exit 1
	;;
esac
cp /etc/config/firewall /tmp/before

# A firewall reload starts the service: nothing changed, so nothing is written.
build
if cmp -s /etc/config/firewall /tmp/before; then
	pass check_a_start_with_nothing_changed_leaves_the_file
else
	fail check_a_start_with_nothing_changed_leaves_the_file "the file changed, sections now in the order $(order)"
fi
if [ -z "$(uci changes firewall)" ]; then
	pass check_a_start_with_nothing_changed_stages_nothing
else
	fail check_a_start_with_nothing_changed_stages_nothing "$(uci changes firewall | tr '\n' ' ')"
fi
# The same again from a file put back, as the drift check's repair does.
cp /tmp/before /etc/config/firewall
build
build
if cmp -s /etc/config/firewall /tmp/before; then
	pass check_starts_in_a_row_leave_the_file
else
	fail check_starts_in_a_row_leave_the_file "the file changed, sections now in the order $(order)"
fi

# A changed port and a second static peer rewrite both rules where they stand: the file differs
# from before only in those values.
cp /tmp/before /etc/config/firewall
uci set rollcall.main.port=7500
uci add_list rollcall.main.peer=198.51.100.4
uci commit rollcall
build
sed -e "s/option dest_port '7500'/option dest_port '7432'/" -e "/list src_ip '198.51.100.4'/d" /etc/config/firewall > /tmp/undone
if cmp -s /tmp/undone /tmp/before && [ "$(uci -q get firewall.rollcall_1.dest_port)" = 7500 ] &&
	[ "$(uci -q get firewall.rollcall_2.src_ip)" = "192.0.2.10 198.51.100.4" ]; then
	pass check_a_change_rewrites_the_rules_in_place
else
	fail check_a_change_rewrites_the_rules_in_place "sections now in the order $(order), rollcall_1 dest_port $(uci -q get firewall.rollcall_1.dest_port), rollcall_2 src_ip $(uci -q get firewall.rollcall_2.src_ip)"
fi

# A rule no longer needed goes, and the other one stays where it is.
uci del_list rollcall.main.peer_zone=wan
uci commit rollcall
cp /etc/config/firewall /tmp/two
build
sed -e "/^config rule 'rollcall_2'/,/^\$/d" /tmp/two > /tmp/one
if [ "$(order)" = "rollcall_1 hermes_net " ] && cmp -s /etc/config/firewall /tmp/one; then
	pass check_a_rule_no_longer_needed_goes_and_the_other_stays
else
	fail check_a_rule_no_longer_needed_goes_and_the_other_stays "sections now in the order $(order)"
fi

exit $rc
CONTAINER
