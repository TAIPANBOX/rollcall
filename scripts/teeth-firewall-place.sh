#!/bin/sh
# teeth-firewall-place.sh -- gate-firewall-place.sh must go red where the builder moves or misses a
# rule.
#
# Each case runs the gate on a copy of the init script with one fault and requires the check named
# for it to go red. The first case is the builder as it was until 2026-11-12, so the output of that
# run is the record of what it did to the file. The clean script is CI's run of the gate just before
# this one. Last, no init script at all must read as measuring nothing.
#
#   ./scripts/teeth-firewall-place.sh
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
GATE=$ROOT/scripts/gate-firewall-place.sh
INIT=$ROOT/packaging/files/etc/init.d/rollcall

# Under dist/, where docker can mount what it needs.
mkdir -p "$ROOT/dist"
T=$(mktemp -d "$ROOT/dist/teeth-firewall-place.XXXXXX")
trap 'rm -rf "$T"' EXIT
rc=0

# plant <name> <sed expression>: a copy of the init script with one fault; fails when the expression
# changed nothing: a fault that plants nothing proves nothing.
plant() {
	sed "$2" "$INIT" > "$T/$1"
	if cmp -s "$INIT" "$T/$1"; then
		echo "TEETH FAIL: '$2' planted nothing in $INIT: the code moved, so move the fault"
		exit 1
	fi
}

expect_red() { # name check
	if out=$("$GATE" "$T/$1" 2>&1); then
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
	printf '%s\n' "$out" | grep '^FAIL ' | sed 's/^/    /'
}

# The builder as it was until 2026-11-12: each rule deleted and added again at every start.
plant delete_and_add 's/^[[:space:]]*rollcall_rule_holds "\$s" "\$@" && return 0$/ uci -q delete "$s"/'
expect_red delete_and_add check_a_start_with_nothing_changed_leaves_the_file

# A rule that differs is deleted and added again instead of rewritten where it stands.
plant changed_rule_moves 's/uci -q delete "\$s\.\$o"/uci -q delete "$s"/'
expect_red changed_rule_moves check_a_change_rewrites_the_rules_in_place

# The values are never compared, so a changed port or static peer leaves the old rule in force.
plant values_ignored 's/^[[:space:]]*\[ "\$(uci -q get "\$s\.\${o%%=\*}")" = "\${o#\*=}" \] || return 1$/ :/'
expect_red values_ignored check_a_change_rewrites_the_rules_in_place

if out=$("$GATE" "$T/absent" 2>&1) || ! printf '%s\n' "$out" | grep -q 'measured nothing'; then
	echo "TEETH FAIL: no init script did not read as measuring nothing"
	printf '%s\n' "$out"
	rc=1
else
	echo "teeth ok: no init script -> measured nothing"
fi

exit $rc
