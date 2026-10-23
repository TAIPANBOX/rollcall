#!/bin/sh
# gate-feed.sh -- the signature has to be the thing that decides.
#
# Invariant:
#
#   "with the feed's public key in /etc/apk/keys, apk installs rollcall and luci-app-rollcall
#   from the feed with no --allow-untrusted, and every file they install is owned by root;
#   without the key, the feed's packages are not installable at all."
#
# Both halves matter and only the second one is easy to get wrong silently. A feed whose
# packages install either way is not a signed feed, it is an unsigned feed with a key file next
# to it, and nothing about the successful install would tell you which one you had built. So
# this runs the same install twice, in a clean OpenWrt 25.12 root file system, and requires it
# to fail the first time.
#
# What "not installable" looks like is worth knowing before you see it: apk does not announce a
# rejected repository. It drops it, and the package then simply does not exist, so the message
# is "no such package" and the count of available packages is quietly lower. The checks assert
# on that, because it is what a person on a router actually meets.
#
#   ./scripts/gate-feed.sh                                       the feed build-feed.sh wrote
#   FEED=https://taipanbox.github.io/rollcall ./scripts/gate-feed.sh     the published feed
#   ARCH=aarch64_generic ./scripts/gate-feed.sh                  another architecture's rootfs
#
# A local feed is mounted read-only and named by its path, as apk names a local repository; a
# published one is read over HTTPS from inside the container, the key fetched with wget the way
# the router fetches it and compared with keys/rollcall.pem before it is trusted. No
# --privileged: it breaks the container's networking, and nothing here needs it.
set -eu

CHECKS='check_refused_without_key check_installs_with_key check_no_allow_untrusted_needed check_files_owned_by_root'

if [ "${1:-}" = "--selftest" ]; then
	n=0; for c in $CHECKS; do echo "$c"; n=$((n + 1)); done
	[ "$n" -gt 0 ] || { echo "measured nothing" >&2; exit 1; }
	exit 0
fi

ROOT=$(cd "$(dirname "$0")/.." && pwd)
ARCH=${ARCH:-x86_64}
RELEASE=${RELEASE:-25.12}
FEED=${FEED:-$ROOT/build/feed/site}
PUB_KEY=${PUB_KEY:-$ROOT/keys/rollcall.pem}
# The newest 25.12 root file systems at the time of writing, pinned by digest. Bump deliberately.
case "$ARCH" in
	x86_64)
		IMAGE=${ROOTFS_IMAGE:-openwrt/rootfs:x86-64-25.12.6@sha256:14401c04218c2e0da0448f099710ada2460636a92395f353351cc616cf3f67af}
		PLATFORM=${PLATFORM:-linux/amd64} ;;
	aarch64_generic)
		IMAGE=${ROOTFS_IMAGE:-openwrt/rootfs:aarch64_generic-25.12.6@sha256:22f13387da208c0fb4150c41f3ec12e34cc5994a0717a49e50aa9f9ae6cb5e7b}
		PLATFORM=${PLATFORM:-linux/aarch64_generic} ;;
	*)
		IMAGE=${ROOTFS_IMAGE:-openwrt/rootfs:$ARCH-25.12.6}
		PLATFORM=${PLATFORM:-linux/$ARCH} ;;
esac

[ -f "$PUB_KEY" ] || { echo "FAIL: measured nothing: no public key at $PUB_KEY"; exit 1; }
KEY_SHA=$(shasum -a 256 "$PUB_KEY" | cut -d' ' -f1)

case "$FEED" in
	https://*)
		MODE=live
		FEED=${FEED%/}
		REPO_LINE="$FEED/$RELEASE/$ARCH/packages.adb"
		MOUNT=""
		echo "PASS: testing the published feed at $FEED" ;;
	*)
		MODE=local
		[ -f "$FEED/$RELEASE/$ARCH/packages.adb" ] || {
			echo "FAIL: measured nothing: no index at $FEED/$RELEASE/$ARCH/packages.adb; run build-feed.sh first"
			exit 1
		}
		[ -f "$FEED/rollcall.pem" ] || { echo "FAIL: measured nothing: no public key in the feed at $FEED"; exit 1; }
		cmp -s "$FEED/rollcall.pem" "$PUB_KEY" || { echo "FAIL: the feed's rollcall.pem is not keys/rollcall.pem"; exit 1; }
		REPO_LINE="/feed/$RELEASE/$ARCH/packages.adb"
		MOUNT="-v $FEED:/feed:ro"
		echo "PASS: feed present for $ARCH at $FEED" ;;
esac
echo "rootfs: $IMAGE"

# shellcheck disable=SC2086 # $MOUNT is empty or one -v pair, split on purpose
docker run --rm -i --platform "$PLATFORM" \
	-v "$ROOT/scripts/apk-retry.sh:/apk-retry.sh:ro" $MOUNT \
	"$IMAGE" /bin/sh -s <<CONTAINER
. /apk-retry.sh
set -eu
fail() { echo "FAIL \$1: \$2"; exit 1; }

mkdir -p /var/lock /var/run /var/state
echo "$REPO_LINE" > /etc/apk/repositories.d/customfeeds.list

# ---- 1. refused without the key
apk update >/tmp/u1.log 2>&1 || true
if apk add rollcall >/tmp/a1.log 2>&1; then
	fail check_refused_without_key "it installed with no key trusted, so the signature decides nothing"
fi
grep -q "rollcall (no such package)" /tmp/a1.log || {
	cat /tmp/u1.log /tmp/a1.log
	fail check_refused_without_key "it failed, but not by the feed being invisible"; }
grep -q "$REPO_LINE: UNTRUSTED signature" /tmp/u1.log || {
	cat /tmp/u1.log
	fail check_refused_without_key "apk update did not name the feed as untrusted, so the refusal is not the signature's"; }
before=\$(grep -oE '[0-9]+ distinct packages' /tmp/u1.log | grep -oE '^[0-9]+' | tail -1)
echo "PASS check_refused_without_key (\${before:-?} packages visible, the feed dropped as UNTRUSTED)"

# ---- 2. installs with the key
if [ "$MODE" = live ]; then
	wget -q -O /tmp/rollcall.pem "$FEED/rollcall.pem" || fail check_installs_with_key "could not fetch $FEED/rollcall.pem"
else
	cp /feed/rollcall.pem /tmp/rollcall.pem
fi
got=\$(sha256sum /tmp/rollcall.pem | cut -d' ' -f1)
[ "\$got" = "$KEY_SHA" ] || fail check_installs_with_key "the feed's key has sha256 \$got, keys/rollcall.pem has $KEY_SHA"
cp /tmp/rollcall.pem /etc/apk/keys/rollcall.pem
apk update >/tmp/u2.log 2>&1 || true
grep -q "UNTRUSTED" /tmp/u2.log && { cat /tmp/u2.log; fail check_installs_with_key "a repository is still untrusted with the key in place"; }
after=\$(grep -oE '[0-9]+ distinct packages' /tmp/u2.log | grep -oE '^[0-9]+' | tail -1)
[ "\${after:-0}" -gt "\${before:-0}" ] || { cat /tmp/u2.log; fail check_installs_with_key "trusting the key did not make more packages visible"; }

# Deliberately no --allow-untrusted: if this needs the flag, the feed is not signed in any way
# that helps, and the whole exercise was decoration.
apk add rollcall luci-app-rollcall >/tmp/a2.log 2>&1 || { cat /tmp/a2.log; fail check_installs_with_key "install failed with the key trusted"; }
apk info -e rollcall >/dev/null 2>&1 || fail check_installs_with_key "rollcall is not registered after the install"
apk info -e luci-app-rollcall >/dev/null 2>&1 || fail check_installs_with_key "luci-app-rollcall is not registered after the install"
echo "PASS check_installs_with_key (\${before:-?} -> \${after:-?} packages)"

# ---- 3. no flag, from this feed, and it runs
grep -q 'allow-untrusted' /tmp/a2.log && fail check_no_allow_untrusted_needed "apk asked for --allow-untrusted"
apk policy rollcall >/tmp/p.log 2>&1 || true
grep -qF "$REPO_LINE" /tmp/p.log || { cat /tmp/p.log; fail check_no_allow_untrusted_needed "apk policy does not name this feed as the source of rollcall"; }
v=\$(/usr/bin/rollcall version 2>&1) || fail check_no_allow_untrusted_needed "installed from the feed but /usr/bin/rollcall does not run: \$v"
echo "PASS check_no_allow_untrusted_needed (\$v)"

# ---- 4. every installed file is root's
n=0
for pkg in rollcall luci-app-rollcall; do
	apk info -L "\$pkg" 2>/dev/null | sed '1d;/^\$/d' > /tmp/files.\$pkg
	[ -s /tmp/files.\$pkg ] || fail check_files_owned_by_root "measured nothing: apk lists no file of \$pkg"
	while IFS= read -r f; do
		# busybox on OpenWrt has no stat; ls -n prints the numeric owner and group.
		owner=\$(ls -ldn "/\$f" | awk '{ print \$3 ":" \$4 }')
		[ -n "\$owner" ] || fail check_files_owned_by_root "/\$f is listed by apk but missing"
		[ "\$owner" = "0:0" ] || fail check_files_owned_by_root "/\$f of \$pkg is owned by \$owner, not 0:0"
		n=\$((n + 1))
	done < /tmp/files.\$pkg
done
echo "PASS check_files_owned_by_root (\$n files of rollcall and luci-app-rollcall, all 0:0)"
CONTAINER

echo "gate-feed: all 4 checks passed ($MODE feed, $ARCH, $IMAGE)"
