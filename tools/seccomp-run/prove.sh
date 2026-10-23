#!/usr/bin/env bash
# prove.sh runs rollcalld for one OpenWrt architecture as it runs on a router, as far as seccomp
# goes: started directly, with no loader and no LD_PRELOAD. The daemon installs its own filter at
# start (internal/sandbox), from the list packaging/seccomp ships for its architecture, because
# procd cannot filter a statically linked program. The script fails when that filter is not in
# force on every thread, when the daemon is killed by SIGSYS, or when it stops for any other
# reason. CI only (.github/workflows/ci.yml, job seccomp): it uses sudo to make /etc/rollcall and
# /var/run/rollcall as the init script does on a router, and to run the CLI as root, as hotplug and
# LuCI do.
#
#   tools/seccomp-run/prove.sh <openwrt-arch> <goarch> [optional]
#
# What it does, in order:
#   0. the configuration laid out as on an OpenWrt 25.12 router: network and system root's alone
#      (0600, network holding a PPPoE password), which the daemon cannot read and must not; root
#      writes the snapshot of the facts it needs (rollcall snapshot), root-owned, mode 0640;
#   1. the daemon as user runner: its own filter in force on every thread (NoNewPrivs 1, Seccomp 2,
#      one filter more than this script runs under, so it is the daemon's own and not inherited),
#      its log naming as many allowed calls as its list holds, the control socket served
#      (rollcall status), the UDP and TCP port bound, a group created with rollcall init and the
#      node started from it, a heartbeat received by a static peer on 127.0.0.2 (so the rtnetlink
#      route lookup ran and picked the lo socket), discovery running on the default-route device
#      (its group socket on ff02::114 bound, no discovery error for it in the status) after init
#      and again after several 5 s socket reconcile passes, alive for 30 s or more;
#   2. rollcall notify going-down and SIGTERM: the daemon must stop with status 0;
#   3. teeth: for each call the daemon makes once its filter is on, a daemon built from a copy of
#      the tree whose lists lack only that call must log one allowed call fewer and be killed by
#      SIGSYS within 20 s, run with GOGC=off and driven by status calls, so its heap grows and the
#      runtime maps memory within seconds rather than hours. prctl (PR_SET_VMA, on each new
#      mapping) is made only where the kernel names anonymous mappings (CONFIG_ANON_VMA_NAME):
#      elsewhere the runtime stops calling it at its first refusal, before the filter is on, so
#      there its teeth are reported as not shown, with the reason.
# With "optional", an architecture this machine cannot execute (AArch32 on an arm64 runner
# without it) is reported as NOT RUN and the script exits 0. Any other failure fails.
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
PID= PEER= TPID=
cleanup() {
	for p in $PID $PEER $TPID; do kill -KILL "$p" 2>/dev/null || true; done
}
trap cleanup EXIT

rm -rf "$WORK"
mkdir -p "$BIN" "$WORK/config" "$WORK/run"
cd "$ROOT"

# Build for the architecture under test, as the release does.
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
	fail "cannot execute linux/$RUN_GOARCH binaries: $out"
fi
echo "architecture: $out; kernel $(uname -r) on $(uname -m)"

# The number of calls the daemon's filter allows: its list, numbered for this architecture. The
# first line of the whole output, not a pipe into head, which pipefail would fail on SIGPIPE.
ALLOWED=$("$BIN/seccomp-run" -allowed)
ALLOWED=${ALLOWED%%$'\n'*}
case $ALLOWED in
'' | *[!0-9]*) fail "seccomp-run -allowed printed '$ALLOWED', not a number" ;;
esac

# seccomp_of prints NoNewPrivs, Seccomp and Seccomp_filters of one status file ("-" for a filter
# count the kernel does not show), or nothing when the file is gone (a thread that ended).
seccomp_of() {
	local st
	st=$(cat "$1" 2>/dev/null) || return 0
	printf '%s\n' "$st" | awk '/^NoNewPrivs:/ { n = $2 } /^Seccomp:/ { s = $2 } /^Seccomp_filters:/ { f = $2 }
		END { if (f == "") f = "-"; print n + 0, s + 0, f }'
}
read -r H_NNP H_MODE H_FILTERS <<EOF
$(seccomp_of /proc/$$/status)
EOF
echo "this script: NoNewPrivs $H_NNP, Seccomp $H_MODE, filters $H_FILTERS"
if [ "$H_FILTERS" = - ] && [ "$H_MODE" != 0 ]; then
	fail "this kernel shows no filter count and this script already runs under seccomp, so the daemon's own filter cannot be told from an inherited one"
fi

# check_filter fails unless the daemon's own filter is in force on every thread of process $1:
# no_new_privs set and seccomp in filter mode on each, with one filter more than this script
# runs under, and its log ($2) naming the number of calls its list allows ($3).
check_filter() {
	local pid=$1 log=$2 want=$3 t nnp mode filters n=0
	for t in /proc/"$pid"/task/*; do
		read -r nnp mode filters <<EOF
$(seccomp_of "$t/status")
EOF
		[ -n "$nnp" ] || continue
		[ "$nnp" = 1 ] && [ "$mode" = 2 ] ||
			fail "thread ${t##*/} of the daemon has NoNewPrivs $nnp and Seccomp $mode: its filter is not on every thread"
		if [ "$H_FILTERS" != - ] && [ "$filters" != $((H_FILTERS + 1)) ]; then
			fail "thread ${t##*/} of the daemon runs under $filters seccomp filters; this script runs under $H_FILTERS, so the daemon's own makes $((H_FILTERS + 1))"
		fi
		n=$((n + 1))
	done
	[ "$n" -gt 0 ] || fail "no thread of the daemon to read"
	grep -q "seccomp filter installed on every thread: $want system calls of linux/$RUN_GOARCH allowed" "$log" ||
		fail "the daemon's log does not say that it installed its filter with the $want calls of its list"
	echo "its own filter in force on all $n threads: NoNewPrivs 1, Seccomp 2, filters $filters (this script: $H_FILTERS); $(grep -m 1 'seccomp filter installed' "$log")"
}

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
printf "config interface 'dsl'\n\toption proto 'pppoe'\n\toption password 'CANARY-123:abc'\n" >"$WORK/config/network"
printf "config system\n\toption zonename 'UTC'\n" >"$WORK/config/system"

# On OpenWrt 25.12 /etc/config/network and /etc/config/system are mode 0600 root: the daemon,
# which runs as runner here and as rollcall on a router, can neither read them nor may it.
sudo chown root:root "$WORK/config/network" "$WORK/config/system"
sudo chmod 0600 "$WORK/config/network" "$WORK/config/system"
if cat "$WORK/config/network" >/dev/null 2>&1; then
	fail "the harness user can read the root-only network file, so this is not the router's layout"
fi

# The directories the init script makes: the control directory and the state, owned by the user
# the daemon runs as, mode 0700.
me=$(id -un)
sudo rm -rf /etc/rollcall /var/run/rollcall
sudo install -d -o "$me" -g "$(id -gn)" -m 0700 /etc/rollcall /var/run/rollcall

# 0. What the init script does before every start: root writes the snapshot of the firewall,
# network and system facts into the control directory, owned by root and the directory's group.
SNAP=/var/run/rollcall/snapshot.json
sudo "$BIN/rollcall" snapshot --config "$WORK/config/rollcall" || fail "rollcall snapshot, run as root, failed"
snapst=$(sudo stat -c '%u %a' "$SNAP")
[ "$snapst" = "0 640" ] || fail "the snapshot is owner and mode '$snapst', not root's with mode 0640"
if sudo grep -q CANARY "$SNAP"; then
	fail "the snapshot carries the network file's PPPoE password"
fi
note "snapshot: written by root, mode 0640, none of the root-only network file's secrets in it"

# 1. The daemon as it runs on a router: started directly, it installs its own filter. The static
# peer on 127.0.0.2 records the first datagram.
python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.2", 7433))
s.settimeout(120)
data, addr = s.recvfrom(4096)
print(len(data), addr[0], addr[1])
' >"$WORK/peer.out" 2>&1 &
PEER=$!
"$BIN/rollcalld" -config "$WORK/config/rollcall" -state /etc/rollcall -run "$WORK/run" >"$WORK/daemon.log" 2>&1 &
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

check_filter "$PID" "$WORK/daemon.log" "$ALLOWED"

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
# The interface hotplug writes the snapshot again while the daemon runs; the rename is atomic.
sudo "$BIN/rollcall" snapshot --config "$WORK/config/rollcall" >/dev/null || fail "rollcall snapshot failed while the daemon ran"
while [ $(($(date +%s) - START)) -lt 30 ]; do
	alive || died "while running"
	sleep 1
done
alive || died "while running"
ran=$(($(date +%s) - START))
status=$(sudo "$BIN/rollcall" status --json) || died "or did not answer rollcall status after $ran s"
check_discovery "after $ran s of passes" "$status"
check_filter "$PID" "$WORK/daemon.log" "$ALLOWED"

# 2. A clean stop, still under the filter.
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
PID=
echo "--- daemon log"
cat "$WORK/daemon.log"
kill "$PEER" 2>/dev/null || true
PEER=
note "run: $ran s with its own filter for linux/$RUN_GOARCH ($ALLOWED calls; in force on every thread, control socket served, UDP and TCP 7432 bound, group created and node started, a heartbeat routed to a static peer, discovery on $dev, network and system root-only and read through the snapshot alone), stopped with status 0"

# 3. Teeth. Each daemon is built from a copy of the tree whose lists lack only one call: it embeds
# the lists as the release build does (TestSeccompDaemonListIsTheProfile), so its filter is the
# shipped one without that call. It runs on the default control socket, so rollcall status reaches
# it, with GOGC=off, so every status call grows its heap and the runtime maps new memory.
SRC=$WORK/src
mkdir -p "$SRC" "$WORK/teeth-state"
tar -C "$ROOT" --exclude=./.git --exclude=./dist -cf - . | tar -C "$SRC" -xf -
drops="prctl eventfd2 epoll_pwait"
case $RUN_GOARCH in
arm | mips | mipsle) drops="$drops futex_time64" ;;
esac
shown= unshown=
for drop in $drops; do
	cp "$ROOT"/packaging/seccomp/*.txt "$SRC/packaging/seccomp/"
	sed -i "/^$drop\$/d" "$SRC"/packaging/seccomp/*.txt
	if sh "$SRC/packaging/seccomp/generate.sh" "$OWRT_ARCH" | grep -q "\"$drop\""; then
		fail "teeth: $drop is still in the copy's $OWRT_ARCH profile"
	fi
	(cd "$SRC" && CGO_ENABLED=0 GOOS=linux GOARCH=$RUN_GOARCH GOARM=$goarm go build -trimpath -o "$BIN/rollcalld-without-$drop" ./cmd/rollcalld)
	log=$WORK/teeth-$drop.log
	GOGC=off "$BIN/rollcalld-without-$drop" -config "$WORK/config/rollcall" -state "$WORK/teeth-state" \
		-run "$WORK/teeth-run" >"$log" 2>&1 &
	TPID=$!
	# named: whether the kernel names the runtime's mappings ("[anon: Go: ...]" in maps), which it
	# does only with CONFIG_ANON_VMA_NAME; unknown until the maps of the live daemon were read.
	named=unknown
	for _ in $(seq 1 20); do
		kill -0 "$TPID" 2>/dev/null || break
		if sudo cat "/proc/$TPID/maps" >"$WORK/teeth-maps" 2>/dev/null && [ -s "$WORK/teeth-maps" ]; then
			if grep -q 'anon: Go:' "$WORK/teeth-maps"; then named=yes; elif [ "$named" = unknown ]; then named=no; fi
		fi
		for _ in 1 2 3 4 5; do sudo "$BIN/rollcall" status --json >/dev/null 2>&1 || true; done
		sleep 1
	done
	kill -KILL "$TPID" 2>/dev/null || true
	reap "$TPID"
	TPID=
	got=$GOT
	count=$(sed -n 's/.*seccomp filter installed on every thread: \([0-9]*\) system calls.*/\1/p;T;q' "$log")
	if [ "$count" != $((ALLOWED - 1)) ]; then
		cat "$log"
		fail "teeth: the daemon built without $drop installed '${count:-no}' allowed calls, not $((ALLOWED - 1)): the copy's list did not reach it"
	fi
	if [ "$got" = SIGSYS ]; then
		echo "teeth: without $drop the daemon ($count calls) was killed by SIGSYS"
		shown="$shown $drop"
	elif [ "$drop" = prctl ] && [ "$named" = no ]; then
		echo "teeth: without prctl the daemon ran 20 s and ended with $got: this kernel names no anonymous mapping ($(grep -h '^# CONFIG_ANON_VMA_NAME\|^CONFIG_ANON_VMA_NAME' "/boot/config-$(uname -r)" 2>/dev/null || echo 'its config not readable')), so the Go runtime stopped calling prctl(PR_SET_VMA) at its first refusal, before the filter was on"
		unshown=" Not shown here: prctl, which this kernel ($(uname -r)) never sees once the filter is on (no CONFIG_ANON_VMA_NAME)."
	else
		echo "kernel names the runtime's mappings: $named"
		echo "--- log of the daemon without $drop"
		cat "$log"
		audit
		fail "teeth: without $drop the daemon ended with $got, not SIGSYS"
	fi
done
note "teeth: the daemon is killed by SIGSYS when its list lacks any of:$shown.$unshown"
note "PASS: $OWRT_ARCH on linux/$RUN_GOARCH, the daemon's own filter, no loader"
