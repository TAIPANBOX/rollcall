#!/bin/sh
# teeth-feed.sh -- gate-feed.sh must go red where the feed is wrong, and stay green where it is not.
#
# Four runs of gate-feed.sh, against copies of the feed build-feed.sh wrote:
#
#   resigned   every package and the index re-signed with a throwaway key, and that key published
#              as the feed's: a sound feed, so the gate must PASS. Without this run the two
#              below could be red for a reason that has nothing to do with them.
#   wrongkey   the same re-signed files, but the feed's key is still keys/rollcall.pem: the
#              signatures are not by the trusted key, so it must FAIL check_installs_with_key.
#   nobody     rollcall replaced by a package of the same name with one file owned by nobody,
#              signed with the throwaway key: it must FAIL check_files_owned_by_root.
#   missing    no feed at all: it must FAIL and say it measured nothing.
#
# The throwaway key is generated inside the container and only its public half leaves it. The
# real private key is never read: nothing here signs with it.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
FEED=${FEED:-$ROOT/build/feed/site}
ARCH=${ARCH:-x86_64}
RELEASE=${RELEASE:-25.12}
ALPINE=${ALPINE:-alpine@sha256:020dfcbaaf4cc1078bf2d9c7ba31a8466e334061dcd2f248001d68f79e52c000}

SRC=$FEED/$RELEASE/$ARCH
[ -f "$SRC/packages.adb" ] || { echo "teeth-feed: measured nothing: no feed at $SRC; run build-feed.sh first" >&2; exit 1; }
PKG=$(cd "$SRC" && ls -1 rollcall-*.apk)
VERSION=${PKG#rollcall-}
VERSION=${VERSION%.apk}

# Under build/, which .gitignore excludes and Docker Desktop can mount.
mkdir -p "$ROOT/build/feed"
T=$(mktemp -d "$ROOT/build/feed/teeth.XXXXXX")
trap 'rm -rf "$T"' EXIT

for m in resigned wrongkey nobody; do
	mkdir -p "$T/$m/$RELEASE/$ARCH"
	cp "$SRC"/luci-app-rollcall-*.apk "$T/$m/$RELEASE/$ARCH/"
done
cp "$SRC/$PKG" "$T/resigned/$RELEASE/$ARCH/"
cp "$SRC/$PKG" "$T/wrongkey/$RELEASE/$ARCH/"
mkdir -p "$T/missing"

docker run --rm -i -v "$ROOT/scripts/apk-retry.sh:/apk-retry.sh:ro" -v "$T:/t" "$ALPINE" /bin/sh -s <<CONTAINER
. /apk-retry.sh
set -eu
apk add -q --no-cache openssl >/dev/null
umask 077
openssl ecparam -name prime256v1 -genkey -noout -out /tmp/throwaway.private.pem
mkdir -p /tmp/keys
openssl ec -in /tmp/throwaway.private.pem -pubout -out /tmp/keys/throwaway.pem 2>/dev/null
umask 022

# rollcall with a file root does not own: a stub CLI so the gate's run check passes, and the
# planted file owned by nobody.
mkdir -p /tree/usr/bin
printf '#!/bin/sh\necho rollcall teeth\n' > /tree/usr/bin/rollcall
echo planted > /tree/usr/bin/planted
chmod 0755 /tree/usr/bin/rollcall
chown -R 0:0 /tree
chown 65534:65534 /tree/usr/bin/planted
apk mkpkg --info name:rollcall --info "version:$VERSION" --info "arch:$ARCH" \
	--files /tree --output "/t/nobody/$RELEASE/$ARCH/rollcall-$VERSION.apk"

for m in resigned wrongkey nobody; do
	cd "/t/\$m/$RELEASE/$ARCH"
	for f in *.apk; do
		apk adbsign --allow-untrusted --reset-signatures --sign-key /tmp/throwaway.private.pem "\$f" >/dev/null
	done
	apk --keys-dir /tmp/keys mkndx --output packages.adb *.apk >/dev/null
	apk adbsign --allow-untrusted --sign-key /tmp/throwaway.private.pem packages.adb >/dev/null
done
cp /tmp/keys/throwaway.pem /t/throwaway.pem
CONTAINER

cp "$T/throwaway.pem" "$T/resigned/rollcall.pem"
cp "$T/throwaway.pem" "$T/nobody/rollcall.pem"
cp "$ROOT/keys/rollcall.pem" "$T/wrongkey/rollcall.pem"

failures=0
# tooth <name> <pass|fail> <text the output must contain> [VAR=value ...]
tooth() {
	name=$1 want=$2 expect=$3
	shift 3
	rc=0
	env "$@" ARCH="$ARCH" RELEASE="$RELEASE" "$ROOT/scripts/gate-feed.sh" > "$T/$name.log" 2>&1 || rc=$?
	ok=1
	case "$want" in
		pass) [ "$rc" -eq 0 ] || ok=0 ;;
		fail) [ "$rc" -ne 0 ] || ok=0 ;;
	esac
	grep -qF "$expect" "$T/$name.log" || ok=0
	if [ "$ok" = 1 ]; then
		echo "PASS tooth $name: gate exit $rc, said \"$expect\""
	else
		echo "FAIL tooth $name: wanted $want with \"$expect\", gate exit $rc; its output:"
		sed 's/^/    /' "$T/$name.log"
		failures=$((failures + 1))
	fi
}

tooth resigned pass "gate-feed: all 4 checks passed" FEED="$T/resigned" PUB_KEY="$T/throwaway.pem"
tooth wrongkey fail "FAIL check_installs_with_key" FEED="$T/wrongkey" PUB_KEY="$ROOT/keys/rollcall.pem"
tooth nobody fail "FAIL check_files_owned_by_root: /usr/bin/planted of rollcall is owned by 65534:65534" FEED="$T/nobody" PUB_KEY="$T/throwaway.pem"
tooth missing fail "measured nothing" FEED="$T/missing" PUB_KEY="$ROOT/keys/rollcall.pem"

[ "$failures" -eq 0 ] || { echo "teeth-feed: $failures of 4 teeth failed"; exit 1; }
echo "teeth-feed: all 4 teeth hold"
