#!/bin/sh
# Writes the seccomp allow-list of one OpenWrt architecture on stdout: common.txt plus the list
# of the architecture's family, sorted, without duplicates. Every profile is the same shape:
# defaultAction SCMP_ACT_KILL_PROCESS, then one SCMP_ACT_ALLOW rule with the names.
#
# Families: amd64 (x86_64), aarch64 (aarch64_*), arm (arm_*), mips (mips_*, mipsel_*).
# scripts/mkipk.sh and scripts/mkapk.sh install this output as /etc/seccomp/rollcall.json in
# each package, so a target never carries another family's names.
#
# Usage: sh packaging/seccomp/generate.sh <openwrt-arch>
set -eu

ARCH=${1:?usage: generate.sh <openwrt-arch>}
DIR=$(cd "$(dirname "$0")" && pwd)

case $ARCH in
	x86_64) FAMILY=amd64 ;;
	aarch64_*) FAMILY=aarch64 ;;
	arm_*) FAMILY=arm ;;
	mips_*|mipsel_*) FAMILY=mips ;;
	*) echo "generate.sh: no seccomp family for $ARCH" >&2; exit 1 ;;
esac

# Names only: comments and blank lines drop out.
names=$(cat "$DIR/common.txt" "$DIR/$FAMILY.txt" \
	| grep -v -e '^#' -e '^[[:space:]]*$' \
	| sed 's/[[:space:]]*$//' \
	| LC_ALL=C sort -u)
if printf '%s\n' "$names" | grep -Evq '^[a-z0-9_]+$'; then
	echo "generate.sh: a name in the $FAMILY lists is not a system call name" >&2
	exit 1
fi

printf '{\n'
printf '  "defaultAction": "SCMP_ACT_KILL_PROCESS",\n'
printf '  "syscalls": [\n'
printf '    {\n      "names": [\n'
printf '%s\n' "$names" | awk 'NR > 1 { printf ",\n" } { printf "        \"%s\"", $0 } END { printf "\n" }'
printf '      ],\n'
printf '      "action": "SCMP_ACT_ALLOW"\n'
printf '    }\n  ]\n}\n'
