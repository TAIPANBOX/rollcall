#!/bin/sh
# publish-feed.sh <tag> -- verify, sign, gate and publish the apk feed from this machine, then
# gate the published copy.
#
#   ./scripts/publish-feed.sh v1.0.0-rc1
#   FROM_RUN=<release.yml run id> ./scripts/publish-feed.sh v1.0.0-rc1   (see build-feed.sh)
#
# Signing does not happen in CI, on purpose.
#
# A signing key held as a repository secret is readable by anyone who can push a workflow to the
# default branch: GitHub masks secrets in logs, and masking is trivial to defeat on purpose. That
# is an acceptable trade for many projects and it is not one for this key, because there is no
# revocation. A router that has trusted the public half keeps trusting anything signed with the
# private half until a person logs in and deletes the file. Nothing published later undoes it.
#
# So CI builds every architecture, compares two builds, attests the release and runs every gate,
# which is what CI is good at, and the signature is applied here, on the machine where the key
# lives and does not travel. Publishing then costs one command.
#
# What this does
#
#   1. refuses a working tree with uncommitted changes, so the page and layout come from a commit
#   2. build-feed.sh: downloads the release's packages, checks them against SHA256SUMS and the
#      build provenance attestation, signs copies, indexes and signs the index
#   3. gate-feed.sh and teeth-feed.sh against the result, before anything is pushed
#   4. refuses any file in the feed that is not the index, a package, the public key or the page
#   5. replaces the gh-pages branch with one fresh commit holding only the feed, and pushes it
#   6. turns GitHub Pages on for that branch if it is not on, waits until the published index is
#      byte-identical to the one just built, and runs gate-feed.sh against the published URL
#
# The packages are not built from this working tree: they are the tag's release set, and the
# attestation ties them to it. What this tree contributes is the scripts and the landing page,
# which is why the tree must be clean and why the commit is named in the published commit.
set -eu

TAG=${1:-}
[ -n "$TAG" ] || { echo "usage: publish-feed.sh <tag>" >&2; exit 1; }

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
REPO=${REPO:-TAIPANBOX/rollcall}
BASE_URL=${BASE_URL:-https://taipanbox.github.io/rollcall}
RELEASE=${RELEASE:-25.12}
SITE=$ROOT/build/feed/site
# The architecture the published copy is first checked on: the one routers have run.
LIVE_PROBE_ARCH=${LIVE_PROBE_ARCH:-aarch64_cortex-a53}

DIRTY=$(git status --porcelain)
[ -z "$DIRTY" ] || {
	echo "publish-feed.sh: the working tree is not clean; commit first:" >&2
	echo "$DIRTY" >&2
	exit 1
}
PUBLISH_SHA=$(git rev-parse HEAD)
PUBLISH_SHORT=$(git rev-parse --short HEAD)
echo "==> publishing $TAG with the scripts of commit $PUBLISH_SHA"

SIGN_KEY=${SIGN_KEY:-$ROOT/keys/rollcall.private.pem}
[ -f "$SIGN_KEY" ] || {
	echo "publish-feed.sh: missing signing key $SIGN_KEY" >&2
	echo "  generate the pair once with: ./scripts/feed-keygen.sh" >&2
	exit 1
}

echo "==> verifying and signing"
SIGN_KEY="$SIGN_KEY" BASE_URL="$BASE_URL" RELEASE="$RELEASE" ./scripts/build-feed.sh "$TAG"

echo "==> gating what is about to be published"
# Before the push rather than after. A feed is the one artefact where "we will notice if it is
# broken" is wrong: the router that notices is someone else's.
FEED="$SITE" RELEASE="$RELEASE" ./scripts/gate-feed.sh
FEED="$SITE" RELEASE="$RELEASE" ./scripts/teeth-feed.sh

# Only what a feed is made of. Finder writes .DS_Store into folders it shows, and a stray file of
# any other kind has no business on a page that routers trust.
stray=$(cd "$SITE" && find . -type f ! -path './index.html' ! -path './rollcall.pem' \
	! -path "./$RELEASE/*/packages.adb" ! -path "./$RELEASE/*/*.apk")
[ -z "$stray" ] || {
	echo "publish-feed.sh: files the feed must not carry; refusing to publish:" >&2
	echo "$stray" >&2
	exit 1
}
if grep -rlq -e '-----BEGIN [A-Z ]*PRIVATE' "$SITE"; then
	echo "publish-feed.sh: something under $SITE holds a private key; refusing to publish" >&2
	exit 1
fi

echo "==> publishing to gh-pages"
# A worktree rather than a branch switch, so an unfinished change in the working tree cannot end
# up in a published feed and the working tree is not disturbed by publishing.
WT=$(mktemp -d)
cleanup() {
	git worktree remove --force "$WT" >/dev/null 2>&1 || true
	rm -rf "$WT"
	# The scratch branch exists only inside the worktree; leaving it behind would make the next
	# run fail on a name that is already taken.
	git branch -qD _feed_publish >/dev/null 2>&1 || true
}
trap cleanup EXIT

# A fresh orphan commit every time, force-pushed, so the branch is always exactly one commit
# deep and holds nothing but the feed. Committing on top of the previous feed would keep every
# version of every package in the repository forever; what a router installs is whatever the
# feed serves now, and the source that produced it has its own history on main.
git worktree add -q --detach "$WT"
git -C "$WT" checkout -q --orphan _feed_publish
git -C "$WT" rm -rq --cached . >/dev/null 2>&1 || true
find "$WT" -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +

cp -R "$SITE/." "$WT/"
# Pages runs Jekyll otherwise, which skips files whose names start with an underscore and can
# mangle what it takes for a template. A feed is bytes, not a site to build.
touch "$WT/.nojekyll"

git -C "$WT" add -A
git -C "$WT" commit -q -m "feed: $TAG, signed on a workstation, scripts at $PUBLISH_SHORT"
# A pre-push hook that scans old..new needs the old gh-pages commit locally.
git fetch -q origin gh-pages 2>/dev/null || true
# Force, because the branch is replaced rather than extended. This is the one place a force push
# is the correct operation and not a way out of a mistake.
git -C "$WT" push -qf origin HEAD:gh-pages
echo "==> pushed gh-pages"

echo "==> GitHub Pages"
# gh prints the 404 body on standard output, so the status decides, not the text.
if ! src=$(gh api "repos/$REPO/pages" --jq '"\(.source.branch) \(.source.path)"' 2>/dev/null); then
	src=none
fi
case "$src" in
	"gh-pages /") echo "Pages already serves gh-pages /" ;;
	none)
		gh api -X POST "repos/$REPO/pages" -f 'source[branch]=gh-pages' -f 'source[path]=/' >/dev/null
		echo "Pages turned on for gh-pages /" ;;
	*)
		gh api -X PUT "repos/$REPO/pages" -f 'source[branch]=gh-pages' -f 'source[path]=/' >/dev/null
		echo "Pages moved from '$src' to gh-pages /" ;;
esac

echo "==> waiting for $BASE_URL to serve this build"
want=$(shasum -a 256 "$SITE/$RELEASE/$LIVE_PROBE_ARCH/packages.adb" | cut -d' ' -f1)
url="$BASE_URL/$RELEASE/$LIVE_PROBE_ARCH/packages.adb"
tries=0
while :; do
	code=$(curl -s -o "$ROOT/build/feed/live.adb" -w '%{http_code}' "$url" || echo 000)
	got=$(shasum -a 256 "$ROOT/build/feed/live.adb" 2>/dev/null | cut -d' ' -f1)
	if [ "$code" = 200 ] && [ "$got" = "$want" ]; then
		echo "$url: 200, the index just built"
		break
	fi
	tries=$((tries + 1))
	[ "$tries" -lt 60 ] || { echo "publish-feed.sh: $url still answers $code after 15 minutes" >&2; exit 1; }
	sleep 15
done
rm -f "$ROOT/build/feed/live.adb"

echo "==> gating the published feed"
FEED="$BASE_URL" RELEASE="$RELEASE" ./scripts/gate-feed.sh
echo "==> published: $BASE_URL/"
