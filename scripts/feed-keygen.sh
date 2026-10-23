#!/bin/sh
# feed-keygen.sh -- make the signing pair for the apk feed. Run once, ever.
#
# apk-tools v3 signs with an elliptic-curve key on prime256v1, the same shape OpenWrt uses for
# its own release keys: /etc/apk/keys/openwrt-25.12.pem on any 25.12 device is a PEM public key
# of exactly this kind. Ed25519, which opkg used through usign, is a different mechanism and
# does not apply to apk.
#
# What each half is for
#
#   public   keys/rollcall.pem. Committed, published with the feed, and copied to
#            /etc/apk/keys on every router that installs from it. Nothing about it is secret.
#   private  keys/rollcall.private.pem, mode 0600. Signs packages and the index. Whoever holds
#            it can publish a package that every router trusting this feed installs without a
#            warning, so it is never committed (.gitignore, and internal/gates/feedkey_test.go
#            fails if one becomes committable), never printed, never uploaded, never a CI
#            secret and never a program argument. Signing happens on the workstation that
#            holds it; see publish-feed.sh for why not in CI.
#
# Rotation is not a formality. If the private key leaks, publishing a new public key does NOT
# undo it: every router still carries the old key in /etc/apk/keys and keeps trusting anything
# signed with it until a person logs in and removes the file. There is no revocation. So:
# generate it once, keep it in one place, and if it is ever in doubt, say so publicly rather
# than quietly rotating.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=${OUT:-$ROOT/keys}
NAME=${NAME:-rollcall}
# The image scripts/mkapk.sh pins. Bump both together.
ALPINE=${ALPINE:-alpine@sha256:020dfcbaaf4cc1078bf2d9c7ba31a8466e334061dcd2f248001d68f79e52c000}

mkdir -p "$OUT"

if [ -f "$OUT/$NAME.pem" ] || [ -f "$OUT/$NAME.private.pem" ]; then
	echo "feed-keygen.sh: $OUT/$NAME.pem or $NAME.private.pem already exists." >&2
	echo "feed-keygen.sh: a second key does not replace the first on any router that" >&2
	echo "feed-keygen.sh: already trusts it. Delete it deliberately if you mean to." >&2
	exit 1
fi

# In a container, so the key is made by a pinned openssl rather than whatever the host happens
# to have, and so no key material is written outside the two files below. Nothing in the
# container prints the private half.
docker run --rm -i -v "$ROOT/scripts/apk-retry.sh:/apk-retry.sh:ro" -v "$OUT:/out" "$ALPINE" /bin/sh -s <<'CONTAINER'
. /apk-retry.sh
set -eu
apk add -q --no-cache openssl >/dev/null
umask 077
openssl ecparam -name prime256v1 -genkey -noout -out /out/private.tmp
openssl ec -in /out/private.tmp -pubout -out /out/public.tmp 2>/dev/null
chmod 600 /out/private.tmp
chmod 644 /out/public.tmp
CONTAINER

mv "$OUT/public.tmp" "$OUT/$NAME.pem"
mv "$OUT/private.tmp" "$OUT/$NAME.private.pem"
chmod 600 "$OUT/$NAME.private.pem"

cat <<EOF

Public key   $OUT/$NAME.pem          commit this, it is published with the feed
Private key  $OUT/$NAME.private.pem  NEVER commit this

.gitignore excludes keys/*.private.pem. The private key stays on this signing workstation and
is never uploaded anywhere, including CI.

Keep a second copy somewhere you would keep a password (the macOS login keychain, as a generic
password, read through standard input, never a command line). There is no way to recover it,
and no way to revoke it from a router that already trusts the public half.
EOF
