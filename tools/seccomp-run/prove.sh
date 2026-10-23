#!/usr/bin/env bash
# prove.sh runs rollcalld under the seccomp profile shipped for one OpenWrt architecture, installed
# as a real kernel filter (kill the process on any call not listed) by seccomp-run, and fails when
# the daemon is killed by SIGSYS or stops for any other reason. CI only (.github/workflows/ci.yml,
# job seccomp): it uses sudo to make /etc/rollcall and /var/run/rollcall as the init script does
# on a router, and to run the CLI as root, as hotplug and LuCI do.
#
#   tools/seccomp-run/prove.sh <openwrt-arch> <goarch> [optional]
#
# What it does, in order:
#   1. teeth: for each call the gate TestSeccompRuntimeSetPerArch names as made at start, the
#      profile without that call must kill the daemon by SIGSYS within 15 s;
#   2. the daemon under the whole profile, as user runner: the filter in force (Seccomp 2,
#      NoNewPrivs 1), the control socket served (rollcall status), the UDP and TCP port bound,
#      a group created with rollcall init and the node started from it, a heartbeat received by
#      a static peer on 127.0.0.2 (so the rtnetlink route lookup ran and picked the lo socket),
#      discovery running on the default-route device (its group socket on ff02::114 bound, no
#      discovery error for it in the status) after init and again after several 5 s socket
#      reconcile passes, alive for 30 s or more;
#   3. rollcall notify going-down and SIGTERM: the daemon must stop with status 0.
# With "optional", a loader this machine cannot execute (AArch32 on an arm64 runner without it)
# is reported as NOT RUN and the script exits 0. Any other failure fails.
set -euo pipefail

OWRT_ARCH=${1:?usage: prove.sh <openwrt-arch> <goarch> [optional]}
RUN_GOARCH=${2:?usage: prove.sh <openwrt-arch> <goarch> [optional]}
OPTIONAL=${3:-}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=${RUNNER_TEMP:-/tmp}/seccomp-$OWRT_ARCH
BIN=$WORK/bin
SOCK=/var/run/rollcall/control.sock

note() { echo "$*"; if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then echo "- $OWRT_ARCH ($RUN_GOARCH): $*" >>"$GITHUB_STEP_SUMMARY"; fi; }
fail() {
	echo "::error::$OWRT_ARCH: $*"
	note "FAIL: $*"
	exit 1
}

# audit prints the kernel's seccomp records (type=1326) with each call's name on this arch.
audit() {
	sudo dmesg 2>/dev/null | grep 'type=1326' | tail -n 5 | while IFS= read -r line; do
		nr=$(printf '%s\n' "$line" | sed -n 's/.* syscall=\([0-9]*\).*/\1/p')
		echo "$line"
		if [ -n "$nr" ]; then echo "  -> system call $nr is $("$BIN/seccomp-run" -name "$nr")"; fi
	done
}

# reap waits for process $1 and sets GOT to its exit status, or SIG<name> when a signal killed
# it. It sets a variable rather than printing, because a command substitution runs in a subshell,
# and a subshell cannot wait for this shell's children.
GOT=
reap() {
	local code=0
	wait "$1" || code=$?
	if [ "$code" -gt 128 ]; then GOT="SIG$(kill -l $((code - 128)))"; else GOT=$code; fi
}

# Nothing this script starts outlives it.
PID= PEER=
cleanup() {
	for p in $PID $PEER; do kill -KILL "$p" 2>/dev/null || true; done
}
trap cleanup EXIT

rm -rf "$WORK"
mkdir -p "$BIN" "$WORK/config" "$WORK/run"
cd "$ROOT"

# 1. Build for the architecture under test, as the release does.
goarm=
[ "$RUN_GOARCH" = arm ] && goarm=7
for c in rollcalld rollcall; do
	CGO_ENABLED=0 GOOS=linux GOARCH=$RUN_GOARCH GOARM=$goarm go build -trimpath -o "$BIN/$c" "./cmd/$c"
done
CGO_ENABLED=0 GOOS=linux GOARCH=$RUN_GOARCH GOARM=$goarm go build -trimpath -o "$BIN/seccomp-run" ./tools/seccomp-run

if ! out=$("$BIN/seccomp-run" -arch 2>&1); then
	if [ "$OPTIONAL" = optional ]; then
		echo "::warning::$OWRT_ARCH not run: this runner cannot execute linux/$RUN_GOARCH: $out"
		note "NOT RUN: this runner cannot execute linux/$RUN_GOARCH binaries ($out)"
		exit 0
	fi
	fail "cannot execute the linux/$RUN_GOARCH loader: $out"
fi
echo "loader: $out; kernel $(uname -r) on $(uname -m)"

sh packaging/seccomp/generate.sh "$OWRT_ARCH" >"$WORK/profile.json"

# A throwaway configuration: the peer zone holds the device of the default route and lo. Two
# static peers get every heartbeat by unicast, each after an rtnetlink route lookup: 127.0.0.2,
# routed through lo, where a listener below must receive one, and 192.0.2.10 (TEST-NET-1),
# routed out of the default device and dropped beyond it.
dev=$(ip -o route show default 2>/dev/null | awk '{print $5; exit}')
[ -n "$dev" ] || fail "no default route on this runner"
cat >"$WORK/config/rollcall" <<EOF
config rollcall 'main'
	option site 'ci'
	list peer_zone 'lan'
	option port '7432'
	list peer '127.0.0.2:7433'
	list peer '192.0.2.10'
	list probe_target '1.1.1.1'
	list probe_target 'dns.google:443'
EOF
cat >"$WORK/config/firewall" <<EOF
config zone
	option name 'lan'
	list device '$dev'
	list device 'lo'
EOF
: >"$WORK/config/network"
printf "config system\n\toption zonename 'UTC'\n" >"$WORK/config/system"

# The directories the init script makes: the control directory and the state, owned by the user
# the daemon runs as, mode 0700.
me=$(id -un)
sudo rm -rf /etc/rollcall /var/run/rollcall
sudo install -d -o "$me" -g "$(id -gn)" -m 0700 /etc/rollcall /var/run/rollcall

# 1. Teeth: each call named as made at start, left out, must kill the daemon by SIGSYS.
drops="prctl eventfd2 epoll_pwait"
case $RUN_GOARCH in
arm | mips | mipsle) drops="$drops brk open futex_time64" ;;
esac
for drop in $drops; do
	"$BIN/seccomp-run" -profile "$WORK/profile.json" -without "$drop" -- "$BIN/rollcalld" \
		-config "$WORK/config/rollcall" -state "$WORK/teeth-state" -run "$WORK/teeth-run" \
		-control "$WORK/teeth.sock" >"$WORK/teeth-$drop.log" 2>&1 &
	pid=$!
	for _ in $(seq 1 15); do
		kill -0 "$pid" 2>/dev/null || break
		sleep 1
	done
	kill -KILL "$pid" 2>/dev/null || true
	reap "$pid"
	got=$GOT
	if [ "$got" != SIGSYS ]; then
		cat "$WORK/teeth-$drop.log"
		fail "teeth: without $drop the daemon ended with $got, not SIGSYS: the harness or the claim that it is made at start is wrong"
	fi
	echo "teeth: without $drop the daemon was killed by SIGSYS"
done
note "teeth: the daemon is killed by SIGSYS without each of: $drops"

# 2. The daemon under the whole profile. The static peer on 127.0.0.2 records the first datagram.
python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.2", 7433))
s.settimeout(120)
data, addr = s.recvfrom(4096)
print(len(data), addr[0], addr[1])
' >"$WORK/peer.out" 2>&1 &
PEER=$!
"$BIN/seccomp-run" -profile "$WORK/profile.json" -- "$BIN/rollcalld" \
	-config "$WORK/config/rollcall" -state /etc/rollcall -run "$WORK/run" >"$WORK/daemon.log" 2>&1 &
PID=$!
START=$(date +%s)

alive() { kill -0 "$PID" 2>/dev/null; }

# discovery_err prints the discovery error a status (JSON, $1) reports for the default-route
# device, or nothing when discovery runs there. The status lists only the devices where it cannot
# run, so a status without the list at all fails rather than reading as "no error".
discovery_err() {
	printf '%s' "$1" | python3 -c '
import json, sys
st = json.load(sys.stdin)
if not isinstance(st.get("discovery"), list):
    sys.exit("the status has no discovery list")
for e in st["discovery"]:
    if e.get("interface") == sys.argv[1]:
        print(e.get("error") or "listed without an error text")
' "$dev" 2>&1
}

# check_discovery fails unless discovery runs on the default-route device, which carries an IPv6
# link-local address on every runner: the group socket on ff02::114 must be bound there.
check_discovery() {
	local derr
	derr=$(discovery_err "$2") || fail "cannot read discovery from the status $1: $derr"
	[ -z "$derr" ] || fail "discovery does not run on $dev $1: $derr"
	echo "discovery runs on $dev $1 (group socket on ff02::114 bound)"
}
ip -6 -o addr show dev "$dev" scope link | grep -q 'inet6 fe80' ||
	fail "$dev has no IPv6 link-local address, so discovery cannot be proven on this runner"

# died reports the daemon's end with its log and the kernel's seccomp records. A daemon still
# running (only a check failed) is killed first, so the wait cannot hang.
died() {
	local got
	if alive; then
		kill -KILL "$PID" 2>/dev/null || true
		wait "$PID" 2>/dev/null || true
		got="nothing (it was still running; the harness killed it)"
	else
		reap "$PID"
		got=$GOT
	fi
	echo "--- daemon log"
	cat "$WORK/daemon.log"
	echo "--- kernel seccomp records"
	audit
	fail "rollcalld ended with $got $1"
}

for _ in $(seq 1 20); do
	alive || died "while starting"
	[ -S "$SOCK" ] && break
	sleep 1
done
[ -S "$SOCK" ] || died "without serving $SOCK within 20 s"

st=$(grep -E '^(Seccomp|Seccomp_filters|NoNewPrivs):' "/proc/$PID/status" | tr -s '\t ' ' ' | tr '\n' ';')
case $st in
*"NoNewPrivs: 1;"*"Seccomp: 2;"*) echo "filter in force: $st" ;;
*) fail "the filter is not in force on the daemon: $st" ;;
esac

status=$(sudo "$BIN/rollcall" status --json) || died "or did not answer rollcall status: $status"
echo "status before init: $status"

sudo "$BIN/rollcall" init --name ci --site ci >"$WORK/init.out" 2>&1 || {
	cat "$WORK/init.out"
	fail "rollcall init failed"
}
for _ in $(seq 1 30); do
	alive || died "after rollcall init"
	status=$(sudo "$BIN/rollcall" status --json) || died "or did not answer rollcall status after init"
	printf '%s' "$status" | grep -Eq '"initialised": ?true' && break
	sleep 1
done
printf '%s' "$status" | grep -Eq '"initialised": ?true' || fail "the node did not start within 30 s of init: $status"
echo "status after init: $status"
check_discovery "after init" "$status"

# A heartbeat to the static peer: the route lookup ran under the filter and chose the lo socket,
# so the datagram comes from 127.0.0.1:7432.
for _ in $(seq 1 30); do
	alive || died "while sending to the static peers"
	[ -s "$WORK/peer.out" ] && break
	sleep 1
done
peer=$(cat "$WORK/peer.out" 2>/dev/null || true)
case $peer in
*" 127.0.0.1 7432") echo "static peer 127.0.0.2:7433 received: $peer (bytes, source address, source port)" ;;
*) fail "the static peer 127.0.0.2:7433 got no heartbeat from 127.0.0.1:7432 within 30 s of the node starting: '$peer'" ;;
esac

udp=$(ss -H -lun "sport = :7432" | wc -l)
tcp=$(ss -H -ltn "sport = :7432" | wc -l)
[ "$udp" -ge 1 ] && [ "$tcp" -ge 1 ] || fail "port 7432 not bound (udp $udp, tcp $tcp sockets)"

sudo "$BIN/rollcall" notify clock-synced >/dev/null 2>&1 || true
while [ $(($(date +%s) - START)) -lt 30 ]; do
	alive || died "while running"
	sleep 1
done
alive || died "while running"
ran=$(($(date +%s) - START))
status=$(sudo "$BIN/rollcall" status --json) || died "or did not answer rollcall status after $ran s"
check_discovery "after $ran s of passes" "$status"

# 3. A clean stop, still under the filter.
sudo "$BIN/rollcall" notify going-down >/dev/null 2>&1 || true
kill -TERM "$PID"
reap "$PID"
got=$GOT
if [ "$got" != 0 ]; then
	echo "--- daemon log"
	cat "$WORK/daemon.log"
	audit
	fail "rollcalld stopped with $got after SIGTERM"
fi
echo "--- daemon log"
cat "$WORK/daemon.log"
kill "$PEER" 2>/dev/null || true
note "PASS: $ran s under the $OWRT_ARCH profile (filter in force, control socket served, UDP and TCP 7432 bound, group created and node started, a heartbeat routed to a static peer, discovery on $dev), stopped with status 0"
