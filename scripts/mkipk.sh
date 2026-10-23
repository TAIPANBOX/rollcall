#!/bin/sh
# Build an opkg .ipk for rollcall, or for luci-app-rollcall, without the OpenWrt SDK.
#
# The SDK exists to cross-compile C against a target toolchain. rollcall is two
# CGO_ENABLED=0 static Go binaries, so nothing needs linking and only the archive format is
# left. An .ipk is an outer gzipped tar holding three members in a fixed order:
#
#   debian-binary   the literal "2.0"
#   control.tar.gz  package metadata and maintainer scripts
#   data.tar.gz     the filesystem tree, rooted at ./
#
# The outer container is a gzipped tar, NOT an ar archive: the opkg that openwrt-mcp was
# checked against (OpenWrt 21.02-SNAPSHOT) refuses the ar form with "Malformed package file".
#
# Usage:
#   OUTDIR=dist/pkg/<arch> ./scripts/mkipk.sh <rollcalld> <rollcall> <version> [arch]
#   OUTDIR=dist/pkg/luci   ./scripts/mkipk.sh --luci <version> [arch]     (arch defaults to all)
set -eu

if [ "${1:-}" = "--luci" ]; then
	PKG=luci-app-rollcall
	VERSION=${2:?usage: mkipk.sh --luci <version> [arch]}
	ARCH=${3:-all}
else
	PKG=rollcall
	DAEMON=${1:?usage: mkipk.sh <rollcalld> <rollcall> <version> [arch]}
	CLI=${2:?usage: mkipk.sh <rollcalld> <rollcall> <version> [arch]}
	VERSION=${3:?usage: mkipk.sh <rollcalld> <rollcall> <version> [arch]}
	# `opkg print-architecture` on the target reports this value.
	ARCH=${4:-aarch64_cortex-a53}
fi
OUTDIR=${OUTDIR:-.}

ROOT=$(cd "$(dirname "$0")/.." && pwd)
FILES=$ROOT/packaging/files
BUILD=$(mktemp -d)
trap 'rm -rf "$BUILD"' EXIT

# make_tar <out.tar> <dir> [list]
#
# A deterministic archive of one directory: root ownership, the epoch as mtime, and a fixed
# member order (the sorted names unless a list is given). GNU tar (Linux, CI) and bsdtar
# (macOS) spell the owner options differently, so both are handled here. `ustar` is what both
# write without extended headers.
make_tar() {
	out=$1
	dir=$2
	list=${3:-}
	find "$dir" -exec env TZ=UTC touch -t 197001010000 {} +
	if [ -z "$list" ]; then
		list=$BUILD/list.$$
		(cd "$dir" && find . | LC_ALL=C sort) > "$list"
	fi
	if tar --version 2>/dev/null | grep -q 'GNU tar'; then
		(cd "$dir" && tar --format=ustar --numeric-owner --owner=0 --group=0 --no-recursion -cf "$out" -T "$list")
	else
		(cd "$dir" && tar --format ustar --uid 0 --gid 0 --uname root --gname root --no-recursion -cf "$out" -T "$list")
	fi
}

# install_tree <source dir> <dest dir>
#
# Every regular file under the source, at mode 0755 when it is executable in the source and
# 0644 otherwise. .DS_Store is never packaged.
install_tree() {
	list=$BUILD/tree.list
	(cd "$1" && find . -type f ! -name .DS_Store | LC_ALL=C sort) > "$list"
	while IFS= read -r f; do
		mode=0644
		if [ -x "$1/$f" ]; then mode=0755; fi
		mkdir -p "$(dirname "$2/$f")"
		install -m "$mode" "$1/$f" "$2/$f"
	done < "$list"
}

# ---- data.tar.gz: the files as they land on the router
DATA=$BUILD/data
mkdir -p "$DATA"
if [ "$PKG" = rollcall ]; then
	mkdir -p "$DATA/usr/bin" "$DATA/etc/init.d" "$DATA/etc/hotplug.d/iface" "$DATA/etc/hotplug.d/ntp" "$DATA/etc/config" \
		"$DATA/etc/uci-defaults" "$DATA/etc/seccomp" "$DATA/etc/capabilities" "$DATA/lib/upgrade/keep.d"
	install -m 0755 "$DAEMON"                                "$DATA/usr/bin/rollcalld"
	install -m 0755 "$CLI"                                   "$DATA/usr/bin/rollcall"
	install -m 0755 "$FILES/etc/init.d/rollcall"             "$DATA/etc/init.d/rollcall"
	install -m 0755 "$FILES/etc/hotplug.d/iface/50-rollcall" "$DATA/etc/hotplug.d/iface/50-rollcall"
	install -m 0755 "$FILES/etc/hotplug.d/ntp/50-rollcall"   "$DATA/etc/hotplug.d/ntp/50-rollcall"
	install -m 0644 "$FILES/etc/config/rollcall"             "$DATA/etc/config/rollcall"
	install -m 0755 "$FILES/etc/uci-defaults/90-rollcall"    "$DATA/etc/uci-defaults/90-rollcall"
	# One profile per architecture, generated from packaging/seccomp: never the same file twice.
	sh "$ROOT/packaging/seccomp/generate.sh" "$ARCH" > "$BUILD/rollcall.seccomp.json"
	install -m 0644 "$BUILD/rollcall.seccomp.json" "$DATA/etc/seccomp/rollcall.json"
	install -m 0644 "$FILES/etc/capabilities/rollcall.json"  "$DATA/etc/capabilities/rollcall.json"
	install -m 0644 "$FILES/lib/upgrade/keep.d/rollcall"     "$DATA/lib/upgrade/keep.d/rollcall"
else
	# LuCI: htdocs lands under /www, and root/ is the router's own root (menu.d and rpcd ACL).
	install_tree "$ROOT/luci-app-rollcall/htdocs" "$DATA/www"
	install_tree "$ROOT/luci-app-rollcall/root"   "$DATA"
fi

# ---- control.tar.gz: metadata and maintainer scripts
CTRL=$BUILD/control
mkdir -p "$CTRL"
if [ "$PKG" = rollcall ]; then
	DEPENDS="procd-seccomp, procd-ujail, ca-bundle"
	SECTION=net
	DESCRIPTION="Watches the routers of one site over the LAN and reports incidents to a chat."
else
	DEPENDS="luci-base, rollcall"
	SECTION=luci
	DESCRIPTION="LuCI pages for rollcall: status, and the administration buttons."
fi
cat > "$CTRL/control" <<EOF
Package: $PKG
Version: $VERSION
Depends: $DEPENDS
Source: https://github.com/TAIPANBOX/rollcall
Section: $SECTION
Architecture: $ARCH
Maintainer: TAIPANBOX
License: MIT
Description: $DESCRIPTION
EOF
if [ "$PKG" = rollcall ]; then
	# Never overwrite a live configuration on upgrade.
	echo "/etc/config/$PKG" > "$CTRL/conffiles"
	install -m 0755 "$ROOT/packaging/postinst" "$CTRL/postinst"
	install -m 0755 "$ROOT/packaging/prerm"    "$CTRL/prerm"
else
	# A LuCI page list is cached per process in /tmp, so a new page does not show until it goes.
	cat > "$CTRL/postinst" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT:-}" ] && exit 0
rm -rf /tmp/luci-indexcache /tmp/luci-modulecache
exit 0
EOF
	chmod 0755 "$CTRL/postinst"
fi

# ---- assemble. gzip -n drops the name and timestamp, so the bytes depend only on the input.
make_tar "$BUILD/control.tar" "$CTRL"
make_tar "$BUILD/data.tar" "$DATA"
gzip -n -9 -c "$BUILD/control.tar" > "$BUILD/control.tar.gz"
gzip -n -9 -c "$BUILD/data.tar" > "$BUILD/data.tar.gz"
echo "2.0" > "$BUILD/debian-binary"

OUT="${PKG}_${VERSION}_${ARCH}.ipk"
OUTER=$BUILD/outer
mkdir -p "$OUTER"
mv "$BUILD/debian-binary" "$BUILD/control.tar.gz" "$BUILD/data.tar.gz" "$OUTER/"
printf '%s\n' ./debian-binary ./control.tar.gz ./data.tar.gz > "$BUILD/outer.list"
make_tar "$BUILD/outer.tar" "$OUTER" "$BUILD/outer.list"
mkdir -p "$OUTDIR"
rm -f "$OUTDIR/$OUT"
gzip -n -9 -c "$BUILD/outer.tar" > "$OUTDIR/$OUT"

echo "$OUTDIR/$OUT"
