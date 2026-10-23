#!/bin/sh
# Build an apk v3 package for rollcall, or for luci-app-rollcall, for OpenWrt 25.12 and later.
#
# mkipk.sh needs no OpenWrt tooling because an .ipk is only an archive. An apk v3 package is
# not an archive: it is a binary ADB blob (one block of schema and metadata, then signature
# and data blocks). Handing apk a renamed .ipk is a different format, and apk says so.
# Exactly one program writes that format, `apk mkpkg` from apk-tools v3, so this script runs
# it. It uses the host's apk when that is v3 and the script runs as root, and otherwise a
# digest-pinned alpine image through docker. apk-tools 2 (alpine 3.22 and earlier) has no mkpkg
# subcommand at all. Every entry of the package is owned by root, and the script checks that in
# the package it wrote (see "give the tree to root" below).
#
# apk refuses an unsigned local file unless the user passes --allow-untrusted. Signing is a
# repository-index concern, and OpenWrt's own package-pack.mk does not sign packages either.
#
# apk versions have no free-form suffix. A release tag is X.Y.Z or X.Y.Z-rcN, and apk
# spells those X.Y.Z and X.Y.Z_rcN. Any other suffix (a local build such as 0.0.0-test) is
# written as X.Y.Z_pre0, which sorts before the release it precedes. The .ipk keeps the
# version as given.
#
# Usage:
#   OUTDIR=dist/pkg/<arch> ./scripts/mkapk.sh <rollcalld> <rollcall> <version> [arch]
#   OUTDIR=dist/pkg/luci   ./scripts/mkapk.sh --luci <version> [arch]    (arch defaults to noarch)
set -eu

if [ "${1:-}" = "--luci" ]; then
	PKG=luci-app-rollcall
	VERSION=${2:?usage: mkapk.sh --luci <version> [arch]}
	ARCH=${3:-noarch}
else
	PKG=rollcall
	DAEMON=${1:?usage: mkapk.sh <rollcalld> <rollcall> <version> [arch]}
	CLI=${2:?usage: mkapk.sh <rollcalld> <rollcall> <version> [arch]}
	VERSION=${3:?usage: mkapk.sh <rollcalld> <rollcall> <version> [arch]}
	# `cat /etc/apk/arch` on the target reports this. It is the OpenWrt package architecture,
	# not the OCI or uname one.
	ARCH=${4:-aarch64_cortex-a53}
fi
# The package release. Bump when the packaging changes but the binary version does not.
PKGREL=${PKGREL:-1}
OUTDIR=${OUTDIR:-.}
DOCKER=${DOCKER:-docker}

# Pinned so a rebuild cannot silently pick up a different apk-tools. Same digest as openwrt-mcp.
# Bump deliberately.
ALPINE=${ALPINE:-alpine@sha256:020dfcbaaf4cc1078bf2d9c7ba31a8466e334061dcd2f248001d68f79e52c000}

case $VERSION in
	*-rc[0-9]*) APKVER=$(printf '%s' "$VERSION" | sed 's/-rc/_rc/') ;;
	*-*) APKVER=$(printf '%s' "$VERSION" | sed 's/-.*$/_pre0/') ;;
	*) APKVER=$VERSION ;;
esac

ROOT=$(cd "$(dirname "$0")/.." && pwd)
FILES=$ROOT/packaging/files
BUILD=$(mktemp -d)
trap 'rm -rf "$BUILD"' EXIT

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

# ---- the file tree, identical to what mkipk.sh stages
#
# The two scripts stage the same tree on purpose. Sharing code would couple them for twenty
# lines of install; the check that matters is the result, and the two packages must agree
# about what lands on the router.
DATA=$BUILD/root
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
	install -m 0644 "$FILES/etc/capabilities/rollcall-none.json" "$DATA/etc/capabilities/rollcall-none.json"
	install -m 0644 "$FILES/lib/upgrade/keep.d/rollcall"     "$DATA/lib/upgrade/keep.d/rollcall"
else
	# LuCI: htdocs lands under /www, and root/ is the router's own root (menu.d and rpcd ACL).
	install_tree "$ROOT/luci-app-rollcall/htdocs" "$DATA/www"
	install_tree "$ROOT/luci-app-rollcall/root"   "$DATA"
fi

# ---- lifecycle scripts
#
# apk's stage names differ from opkg's. post-install covers a fresh install and an upgrade;
# pre-deinstall is opkg's prerm. The rollcall scripts are the same files mkipk.sh puts in
# control.tar.gz, and they carry their own guards: apk runs them inside the target root, so
# there is no IPKG_INSTROOT to test.
SCRIPTS=""
if [ "$PKG" = rollcall ]; then
	install -m 0755 "$ROOT/packaging/postinst" "$BUILD/post-install"
	install -m 0755 "$ROOT/packaging/prerm"    "$BUILD/pre-deinstall"
	DEPENDS="procd-seccomp procd-ujail ca-bundle"
	DESCRIPTION="Watches the routers of one site over the LAN and reports incidents to a chat."
	SCRIPTS="--script post-install:$BUILD/post-install --script pre-deinstall:$BUILD/pre-deinstall"
else
	cat > "$BUILD/post-install" <<'EOF'
#!/bin/sh
rm -rf /tmp/luci-indexcache /tmp/luci-modulecache
exit 0
EOF
	chmod 0755 "$BUILD/post-install"
	DEPENDS="luci-base rollcall"
	DESCRIPTION="LuCI pages for rollcall: status, and the administration buttons."
	SCRIPTS="--script post-install:$BUILD/post-install"
fi

# ---- find a writer for the format, and give the tree to root
#
# An apk names the owner of every entry, and `apk mkpkg` has no option to set it: apk-tools
# 3.0.7 takes the uid and gid of each file and directory of the staged tree and names them from
# the passwd and group files of the system it runs on, and writes nobody for an id it cannot
# name. On a CI runner the tree is staged by the runner's user (uid 1001) and named inside the
# alpine image, which has no such user, so every entry of the first lab packages was installed
# owned by nobody:nogroup, /etc/init.d/rollcall and /usr/bin/rollcall (both run as root)
# included. So mkpkg reads a copy of the tree owned by root, and check_owners below reads the
# result back.
#
# A host apk is used only when it is v3 and this script runs as root, the one case where the
# staged tree is root's already. apk-tools 2 has no mkpkg subcommand and `apk mkpkg --help`
# exits 1 on v3 as well, so the help text is the probe, not the exit status. Anything else runs
# in the pinned image, as root there, on a copy made inside the container: the bind-mounted
# tree is never chowned, so the runner can still delete it.
if [ "$(id -u)" = 0 ] && command -v apk >/dev/null 2>&1 && apk mkpkg --help 2>/dev/null | grep -q 'Mkpkg options'; then
	HOST_APK=1
elif command -v "$DOCKER" >/dev/null 2>&1; then
	HOST_APK=0
else
	echo "mkapk.sh: need apk-tools v3 on PATH and root, or docker to run $ALPINE" >&2
	echo "mkapk.sh: apk v3 is the only writer of the package format; see the header" >&2
	exit 1
fi

# in_writer <command> [args]: runs a command where apk-tools v3 is, as root.
in_writer() {
	if [ "$HOST_APK" = 1 ]; then
		"$@"
	else
		"$DOCKER" run --rm -v "$BUILD:$BUILD" -w "$BUILD" "$ALPINE" "$@"
	fi
}

# run_mkpkg <mkpkg options>: apk mkpkg over a root-owned copy of $DATA.
run_mkpkg() {
	# shellcheck disable=SC2016 # expanded by the inner shell, which gets the paths as arguments
	in_writer sh -c 'set -e; src=$1; stage=$(mktemp -d); shift; cp -a "$src/." "$stage/"; chown -R 0:0 "$stage"; apk mkpkg --files "$stage" "$@"; rm -rf "$stage"' \
		sh "$DATA" "$@"
}

# check_owners <package>: fails unless every entry of the package, files and directories, is
# owned by user root and group root, as apk itself lists them.
check_owners() {
	in_writer apk adbdump "$1" > "$BUILD/adbdump.txt"
	acls=$(grep -c '^[[:space:]]*\(- \)\{0,1\}acl:' "$BUILD/adbdump.txt" || true)
	users=$(grep -c '^[[:space:]]*user: root$' "$BUILD/adbdump.txt" || true)
	groups=$(grep -c '^[[:space:]]*group: root$' "$BUILD/adbdump.txt" || true)
	if [ "$acls" -eq 0 ] || [ "$users" -ne "$acls" ] || [ "$groups" -ne "$acls" ]; then
		echo "mkapk.sh: $(basename "$1"): $acls entries, $users owned by user root, $groups by group root; every entry must be root's:" >&2
		grep -E '^[[:space:]]*(user|group):' "$BUILD/adbdump.txt" | grep -v ': root$' | sort | uniq -c >&2 || true
		exit 1
	fi
}

OUT="${PKG}-${APKVER}-r${PKGREL}-${ARCH}.apk"
# shellcheck disable=SC2086 # $SCRIPTS is a list of --script pairs, split on purpose
run_mkpkg \
	--info "name:$PKG" \
	--info "version:$APKVER-r$PKGREL" \
	--info "arch:$ARCH" \
	--info "license:MIT" \
	--info "origin:$PKG" \
	--info "url:https://github.com/TAIPANBOX/rollcall" \
	--info "maintainer:TAIPANBOX" \
	--info "description:$DESCRIPTION" \
	--info "depends:$DEPENDS" \
	$SCRIPTS \
	--output "$BUILD/$OUT"
check_owners "$BUILD/$OUT"

mkdir -p "$OUTDIR"
rm -f "$OUTDIR/$OUT"
cp "$BUILD/$OUT" "$OUTDIR/$OUT"

echo "$OUTDIR/$OUT"
