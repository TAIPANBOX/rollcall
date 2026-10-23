#!/bin/sh
# build-feed.sh <tag> -- verify a release's packages, sign copies of them, index them, and lay
# out a publishable apk feed for OpenWrt 25.12 under build/feed/site.
#
#   SIGN_KEY=keys/rollcall.private.pem ./scripts/build-feed.sh v1.0.0-rc1
#
# Where the packages come from
#
# Nothing is built here. The packages are the ones release.yml built from the tag, two builds
# compared byte for byte, and attested in one build-provenance statement over every file. They
# are downloaded with gh into build/feed/download/<tag>, never into the repository root, and
# checked before anything else touches them: each .apk against SHA256SUMS, and each .apk and
# SHA256SUMS itself against the attestation, which must come from release.yml at this very tag
# on a GitHub-hosted runner. A file that fails either check stops the build.
#
# FROM_RUN=<run id> takes the same files from the release-set artifact of that release.yml run
# instead of the release page, for a run whose packages were built and attested but whose
# release was not created. The checks are the same: the attestation, not the place the file
# was fetched from, is what ties it to the tag.
#
# Why sign at all
#
# An unsigned package installs only with `apk add --allow-untrusted`, a flag people learn to type
# by reflex and then keep typing at the one moment it matters. A signed feed removes the flag
# from the instructions: the key is added once, and after that `apk add rollcall` either
# verifies or fails.
#
# The order matters, and the error message does not say so
#
# `apk mkndx` refuses to index a package whose signature it does not trust, so the packages are
# signed FIRST and the index second. Running mkndx on unsigned packages gives "UNTRUSTED
# signature ... not creating index", which reads like a problem with the key rather than with
# the order.
#
# Reading an unsigned input needs --allow-untrusted even while writing a signature. Without it
# adbsign fails, and it fails after having already truncated its file, because it rewrites in
# place. So this script signs COPIES under build/feed/site and never the downloaded originals.
#
# Layout, the same as the sibling feed of hermes-openwrt:
#
#   site/rollcall.pem                          the public key, for /etc/apk/keys
#   site/index.html                            how a person adds the feed
#   site/25.12/<arch>/packages.adb             the signed index of that architecture
#   site/25.12/<arch>/rollcall-<version>.apk   the daemon and CLI, signed
#   site/25.12/<arch>/luci-app-rollcall-<version>.apk
#
# The release names its files <name>-<version>-<arch>.apk. A feed's files are named
# <name>-<version>.apk, because that is the name apk asks a repository for; each architecture has
# its own directory, so the names do not collide.
#
# The noarch LuCI package is copied into every architecture's directory: apk resolves a
# repository per architecture, and a shared noarch directory would never be looked in.
set -eu

TAG=${1:-}
printf '%s\n' "$TAG" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-rc[0-9]+)?$' || {
	echo "usage: build-feed.sh <tag>, a release tag vX.Y.Z or vX.Y.Z-rcN" >&2
	exit 1
}

ROOT=$(cd "$(dirname "$0")/.." && pwd)
REPO=${REPO:-TAIPANBOX/rollcall}
RELEASE=${RELEASE:-25.12}
WORK=$ROOT/build/feed
DL=$WORK/download/$TAG
OUT=$WORK/site
BASE_URL=${BASE_URL:-https://taipanbox.github.io/rollcall}
# The architectures rollcall has run on, on real routers. Every other one is listed as built only.
HARDWARE_ARCHES=${HARDWARE_ARCHES:-aarch64_cortex-a53}
# The image scripts/mkapk.sh pins: the apk-tools v3 that wrote the packages also signs them.
ALPINE=${ALPINE:-alpine@sha256:020dfcbaaf4cc1078bf2d9c7ba31a8466e334061dcd2f248001d68f79e52c000}

# The private key never lives in the repository's history and never reaches CI: signing happens
# only on the workstation that holds it. See publish-feed.sh for why.
SIGN_KEY=${SIGN_KEY:-$ROOT/keys/rollcall.private.pem}
PUB_KEY=${PUB_KEY:-$ROOT/keys/rollcall.pem}
[ -f "$SIGN_KEY" ] || {
	echo "build-feed.sh: no signing key at $SIGN_KEY; set SIGN_KEY, or make the pair once with" >&2
	echo "  ./scripts/feed-keygen.sh" >&2
	exit 1
}
[ -f "$PUB_KEY" ] || { echo "build-feed.sh: no public key at $PUB_KEY" >&2; exit 1; }
# The two halves must belong together, or every router would refuse what this signs. The
# private half goes to openssl as a file name, never as text.
if command -v openssl >/dev/null 2>&1; then
	openssl ec -in "$SIGN_KEY" -pubout 2>/dev/null | cmp -s - "$PUB_KEY" || {
		echo "build-feed.sh: $SIGN_KEY is not the private half of $PUB_KEY" >&2
		exit 1
	}
fi

# apk spells -rcN as _rcN; mkapk.sh does the same.
VER=${TAG#v}
APKVER=$(printf '%s' "$VER" | sed 's/-rc/_rc/')
APKVER_RE=$(printf '%s' "$APKVER" | sed 's/[.]/\\./g')

# ---- 1. download and verify the release's packages
FROM_RUN=${FROM_RUN:-}
rm -rf "$DL"
mkdir -p "$DL"
if [ -n "$FROM_RUN" ]; then
	run=$(gh run view "$FROM_RUN" --repo "$REPO" --json headBranch,event,workflowName --jq '"\(.headBranch) \(.event) \(.workflowName)"')
	[ "$run" = "$TAG push release" ] || {
		echo "build-feed.sh: run $FROM_RUN is '$run', not release.yml pushed for $TAG" >&2
		exit 1
	}
	echo "==> downloading the packages of $REPO $TAG from the release-set artifact of run $FROM_RUN"
	ART=$WORK/download/run-$FROM_RUN
	rm -rf "$ART"
	gh run download "$FROM_RUN" --repo "$REPO" -n release-set -D "$ART"
	cp "$ART"/*.apk "$ART/SHA256SUMS" "$DL/"
	rm -rf "$ART"
	SOURCE_URL="https://github.com/$REPO/actions/runs/$FROM_RUN"
	SOURCE_TEXT="the run"
else
	echo "==> downloading the packages of $REPO $TAG"
	gh release download "$TAG" --repo "$REPO" --dir "$DL" --pattern '*.apk' --pattern SHA256SUMS
	SOURCE_URL="https://github.com/$REPO/releases/tag/$TAG"
	SOURCE_TEXT="the release page"
fi

# An allow-list of names, and a refusal rather than a skip: a file nobody named means the
# release is not what this script believes it is, and the feed should not be built on that.
for f in "$DL"/*; do
	name=$(basename "$f")
	case "$name" in
		SHA256SUMS) ;;
		*) printf '%s\n' "$name" | grep -Eq "^(rollcall-${APKVER_RE}-r[0-9]+-[a-z0-9_-]+|luci-app-rollcall-${APKVER_RE}-r[0-9]+-noarch)\.apk\$" || {
			echo "build-feed.sh: $name is not a package of $TAG this feed publishes" >&2
			exit 1
		} ;;
	esac
done

# The .apk lines of SHA256SUMS, and exactly the .apk files downloaded: none missing, none extra.
awk '{ n = $2; sub(/^\*/, "", n); if (n ~ /\.apk$/) print }' "$DL/SHA256SUMS" > "$WORK/apk.sha256"
listed=$(awk '{ n = $2; sub(/^\*/, "", n); print n }' "$WORK/apk.sha256" | LC_ALL=C sort)
present=$(cd "$DL" && ls -1 ./*.apk 2>/dev/null | sed 's|^\./||' | LC_ALL=C sort)
[ -n "$present" ] || { echo "build-feed.sh: $TAG has no .apk assets" >&2; exit 1; }
[ "$listed" = "$present" ] || {
	echo "build-feed.sh: the .apk files of $TAG and the .apk lines of its SHA256SUMS differ:" >&2
	printf 'SHA256SUMS:\n%s\ndownloaded:\n%s\n' "$listed" "$present" >&2
	exit 1
}
echo "==> checksums"
(cd "$DL" && shasum -a 256 -c "$WORK/apk.sha256")

echo "==> attestations (release.yml at refs/tags/$TAG, GitHub-hosted)"
for f in "$DL"/*.apk "$DL/SHA256SUMS"; do
	if ! gh attestation verify "$f" --repo "$REPO" \
		--signer-workflow "$REPO/.github/workflows/release.yml" \
		--source-ref "refs/tags/$TAG" --deny-self-hosted-runners >"$WORK/attest.log" 2>&1; then
		cat "$WORK/attest.log" >&2
		echo "build-feed.sh: $(basename "$f") has no valid attestation from release.yml at $TAG" >&2
		exit 1
	fi
	echo "verified: $(basename "$f")"
done

# ---- 2. lay out copies per architecture
LUCI=$(cd "$DL" && ls -1 luci-app-rollcall-*-noarch.apk)
[ "$(printf '%s\n' "$LUCI" | wc -l | tr -d ' ')" = 1 ] || {
	echo "build-feed.sh: expected exactly one luci-app-rollcall noarch package, found: $LUCI" >&2
	exit 1
}
ARCHES=$(cd "$DL" && ls -1 rollcall-*.apk | sed -n "s/^rollcall-${APKVER_RE}-r[0-9][0-9]*-\(.*\)\.apk\$/\1/p" | LC_ALL=C sort)
[ -n "$ARCHES" ] || { echo "build-feed.sh: no rollcall package in $TAG" >&2; exit 1; }

rm -rf "$OUT"
for arch in $ARCHES; do
	dir="$OUT/$RELEASE/$arch"
	mkdir -p "$dir"
	n=0
	for f in "$DL"/rollcall-*-"$arch".apk; do cp "$f" "$dir/"; n=$((n + 1)); done
	[ "$n" = 1 ] || { echo "build-feed.sh: $n rollcall packages for $arch, expected 1" >&2; exit 1; }
	cp "$DL/$LUCI" "$dir/"
done

# ---- 3. sign the packages, then index and sign the index
#
# One container for all of it, with the private key mounted read-only by path and only this
# feed's public key in the key directory apk consults, so mkndx and verify accept a signature by
# this key and by nothing else.
echo "==> signing in $ALPINE"
docker run --rm -i \
	-v "$OUT:/feed" \
	-v "$SIGN_KEY:/keys/private.pem:ro" \
	-v "$PUB_KEY:/ourkeys/rollcall.pem:ro" \
	"$ALPINE" /bin/sh -s <<CONTAINER
set -eu
for dir in /feed/$RELEASE/*; do
	[ -d "\$dir" ] || continue
	arch=\$(basename "\$dir")
	cd "\$dir"
	for f in *.apk; do
		apk adbdump "\$f" > /tmp/info
		name=\$(sed -n 's/^  name: //p' /tmp/info | head -n 1)
		version=\$(sed -n 's/^  version: //p' /tmp/info | head -n 1)
		got=\$(sed -n 's/^  arch: //p' /tmp/info | head -n 1)
		# A package whose own arch is not its directory's is never offered by apk there.
		case "\$name" in
			luci-app-rollcall) want=noarch ;;
			rollcall) want=\$arch ;;
			*) echo "\$arch/\$f is package '\$name', not one this feed publishes" >&2; exit 1 ;;
		esac
		[ "\$got" = "\$want" ] || { echo "\$arch/\$f declares arch '\$got', not '\$want'" >&2; exit 1; }
		# apk fetches a package from a repository as <name>-<version>.apk, its default package
		# name spec, with no architecture in it: the release's file names carry the architecture,
		# so the copy is renamed or apk answers "package mentioned in index not found".
		[ "\$f" = "\$name-\$version.apk" ] || mv "\$f" "\$name-\$version.apk"
		f=\$name-\$version.apk
		# --allow-untrusted describes the INPUT, not the output: the package has no signature
		# yet, and without the flag adbsign refuses and leaves a truncated file behind.
		apk adbsign --allow-untrusted --sign-key /keys/private.pem "\$f" >/dev/null
	done
	apk --keys-dir /ourkeys mkndx --description "rollcall $TAG" --output packages.adb *.apk >/dev/null
	apk adbsign --allow-untrusted --sign-key /keys/private.pem packages.adb >/dev/null
	apk --keys-dir /ourkeys verify *.apk packages.adb >/dev/null
	echo "==> \$arch: index \$(stat -c %s packages.adb) bytes, \$(ls *.apk | wc -l) packages, signatures verified"
done
CONTAINER

# ---- 4. the key and the landing page
#
# The public key travels with the feed so the instructions are two lines, not a search.
cp "$PUB_KEY" "$OUT/rollcall.pem"
KEY_SHA=$(shasum -a 256 "$PUB_KEY" | cut -d' ' -f1)

arch_items=""
for arch in $ARCHES; do
	case " $HARDWARE_ARCHES " in
		*" $arch "*) note="has run on routers" ;;
		*) note="built and signed, not yet run on a router" ;;
	esac
	arch_items="$arch_items<li><code>$arch</code>: $note</li>"
done
PRERELEASE=""
case "$TAG" in *-rc*) PRERELEASE=" This is a release candidate." ;; esac

cat > "$OUT/index.html" <<HTML
<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>rollcall feed</title>
<style>
body{font:16px/1.6 system-ui,sans-serif;max-width:46rem;margin:2.5rem auto;padding:0 16px;color:#1d1d1f;background:#fff}
code,pre{background:#f2f2f2;border-radius:3px}code{padding:.1rem .3rem}
pre{padding:.8rem;overflow-x:auto;white-space:pre}h2{margin-top:2rem}
@media (prefers-color-scheme: dark){body{color:#e8e8e8;background:#161616}code,pre{background:#262626}a{color:#8ab4f8}}
</style>
<h1>rollcall</h1>
<p>A signed apk feed for OpenWrt 25.12 with
<a href="https://github.com/TAIPANBOX/rollcall">rollcall and luci-app-rollcall</a>: the routers of
one site watch each other over the LAN and report incidents to a chat.</p>
<p>Current release: <a href="https://github.com/$REPO/tree/$TAG">$TAG</a>
(apk version $APKVER).$PRERELEASE</p>

<h2>Add the feed</h2>
<p>On the router, as root. The first line trusts the key, the second adds the feed for the
router's own architecture.</p>
<pre>wget -O /etc/apk/keys/rollcall.pem $BASE_URL/rollcall.pem
echo "$BASE_URL/$RELEASE/\$(cat /etc/apk/arch)/packages.adb" &gt;&gt; /etc/apk/repositories.d/customfeeds.list

apk update &amp;&amp; apk add rollcall luci-app-rollcall</pre>
<p>The key's SHA-256, to compare with <code>sha256sum /etc/apk/keys/rollcall.pem</code>:</p>
<pre>$KEY_SHA</pre>
<p>The index and every package are signed with that key. Without it apk drops the feed without a
word and the packages appear not to exist. Nothing above needs <code>--allow-untrusted</code>.
After the install the service is enabled and not started; the
<a href="https://github.com/$REPO#install">README</a> goes on from there with
<code>rollcall init</code>.</p>

<h2>Architectures</h2>
<ul>$arch_items</ul>
<p>The packages are the ones the release workflow built from the tag
(<a href="$SOURCE_URL">$SOURCE_TEXT</a>).
Each was checked against the release checksums and its build provenance attestation before it
was signed for this feed, so the files here differ from those originals by the signature.</p>
</html>
HTML

echo "==> feed at $OUT ($(du -sh "$OUT" | cut -f1)), arches: $(echo $ARCHES)"
