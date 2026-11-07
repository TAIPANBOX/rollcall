#!/bin/sh
# teeth-upgrade.sh -- gate-upgrade.sh must go red where a package is wrong.
#
# Each case builds the package from a scratch copy with one fault and requires the check named for
# it to go red. The first case is the package as it shipped until post-upgrade existed, so the
# output of that run is the record of what such a package loses. The clean package is CI's run of
# the gate just before this one. Last, no packages at all must read as measuring nothing.
#
#   ./scripts/teeth-upgrade.sh <rollcalld> <rollcall> <version> [arch]
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
DAEMON=$(cd "$(dirname "${1:?usage: teeth-upgrade.sh <rollcalld> <rollcall> <version> [arch]}")" && pwd)/$(basename "$1")
CLI=$(cd "$(dirname "${2:?usage}")" && pwd)/$(basename "$2")
VERSION=${3:?usage}
ARCH=${4:-x86_64}
GATE=$ROOT/scripts/gate-upgrade.sh

# Under dist/, where the docker of mkapk.sh and of the gate can mount what it needs.
mkdir -p "$ROOT/dist"
T=$(mktemp -d "$ROOT/dist/teeth-upgrade.XXXXXX")
trap 'rm -rf "$T"' EXIT
rc=0

# plant <file> <sed expression>: changes the file, and fails when the expression changed nothing:
# a fault that plants nothing proves nothing.
plant() {
	sed "$2" "$1" > "$1.new"
	if cmp -s "$1" "$1.new"; then
		echo "TEETH FAIL: '$2' planted nothing in $1: the code moved, so move the fault"
		exit 1
	fi
	cat "$1.new" > "$1"
	rm -f "$1.new"
}

fresh() { # name
	d=$T/$1
	mkdir -p "$d"
	cp -R "$ROOT/scripts" "$ROOT/packaging" "$ROOT/luci-app-rollcall" "$d/"
}

expect_red() { # what check
	OUTDIR="$d/out" "$d/scripts/mkapk.sh" "$DAEMON" "$CLI" "$VERSION" "$ARCH" >/dev/null
	OUTDIR="$d/out" PKGREL=2 "$d/scripts/mkapk.sh" "$DAEMON" "$CLI" "$VERSION" "$ARCH" >/dev/null
	if out=$("$GATE" "$d"/out/rollcall-*-r1-*.apk "$d"/out/rollcall-*-r2-*.apk 2>&1); then
		echo "TEETH FAIL: $1 did not make the gate go red"
		printf '%s\n' "$out"
		rc=1
		return
	fi
	if ! printf '%s\n' "$out" | grep -q "^FAIL $2:"; then
		echo "TEETH FAIL: $1 went red, but not at $2"
		printf '%s\n' "$out"
		rc=1
		return
	fi
	echo "teeth ok: $1 -> $2"
}

fresh no-post-upgrade
plant "$d/scripts/mkapk.sh" 's/ --script post-upgrade:$BUILD\/post-upgrade//'
expect_red "post-upgrade omitted" check_upgrade_restarts_an_enabled_service
printf '%s\n' "$out" | grep -E '^(PASS|FAIL) |^  apk:|^  the init script' | sed 's/^/  | /'

fresh enables
plant "$d/packaging/postinst" 's/^\[ "${PKG_UPGRADE:-0}" = 1 \] || \/etc\/init.d\/rollcall enable$/\/etc\/init.d\/rollcall enable/'
expect_red "an upgrade that enables" check_upgrade_leaves_a_disabled_service_off

fresh restarts-disabled
plant "$d/packaging/postinst" 's/ && \/etc\/init.d\/rollcall enabled; then/; then/'
expect_red "a restart of a service that is not enabled" check_upgrade_leaves_a_disabled_service_off

fresh no-account
plant "$d/packaging/postinst" '/^user_exists rollcall/s/^/[ "${PKG_UPGRADE:-0}" = 1 ] || /'
expect_red "an upgrade that does not make the account" check_upgrade_makes_the_account

if out=$("$GATE" "$T/none.apk" "$T/none.apk" 2>&1); then
	echo "TEETH FAIL: the gate is green with no package"
	rc=1
elif printf '%s\n' "$out" | grep -q "measured nothing"; then
	echo "teeth ok: no package reads as measured nothing"
else
	echo "TEETH FAIL: red, but not measured nothing: $out"
	rc=1
fi

[ "$rc" -eq 0 ] && echo "teeth-upgrade: every planted fault went red at its check"
exit "$rc"
