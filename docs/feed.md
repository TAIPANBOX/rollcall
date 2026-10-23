# The signed apk feed

rollcall's packages for OpenWrt 25.12 are served as a signed apk feed from GitHub Pages:
<https://taipanbox.github.io/rollcall/>. The index and every package in it are signed, so apk
installs them with no `--allow-untrusted`, and refuses them without the key.

## Add it to a router

On the router, as root:

```sh
wget -O /etc/apk/keys/rollcall.pem https://taipanbox.github.io/rollcall/rollcall.pem
echo "https://taipanbox.github.io/rollcall/25.12/$(cat /etc/apk/arch)/packages.adb" >> /etc/apk/repositories.d/customfeeds.list
apk update && apk add rollcall luci-app-rollcall
```

The first line trusts the key, the second adds the feed for the router's own architecture. The
key is [keys/rollcall.pem](../keys/rollcall.pem); its SHA-256 is

```
1dd696c7afce0464688a5106229723f60c8cfb9bd2f6ec296ee5fec24f57ff39
```

and `sha256sum /etc/apk/keys/rollcall.pem` on the router prints the same. Without the key apk
drops the feed without a word: `apk add rollcall` then says `rollcall (no such package)`.

Architectures: every target in the Makefile (`aarch64_cortex-a53`, `aarch64_generic`,
`arm_cortex-a7`, `arm_cortex-a9`, `mips_24kc`, `mipsel_24kc`, `x86_64`). rollcall has run on
routers of one of them, `aarch64_cortex-a53`.

## How a release gets into the feed

```sh
./scripts/publish-feed.sh v1.0.0-rc1
```

1. **Download and verify.** `scripts/build-feed.sh` downloads the tag's `.apk` files, which
   `release.yml` built (two builds compared byte for byte), and checks each against
   `SHA256SUMS` and against the release's build provenance attestation, which must come from
   `release.yml` at that tag on a GitHub-hosted runner. `SHA256SUMS` is checked against the
   attestation too. A file that fails stops the build. `FROM_RUN=<run id>` takes the same files
   from the run's `release-set` artifact instead of the release page; the checks do not change.
2. **Sign copies.** In the alpine image `scripts/mkapk.sh` pins, apk-tools v3 signs every
   package, then builds the index of each architecture with `apk mkndx` and signs it. Packages
   first: mkndx refuses a package it cannot verify. The copies are named
   `<name>-<version>.apk`, the name apk asks a repository for; the release's own names carry
   the architecture, and apk does not find those. The LuCI package is `noarch` and is copied
   into every architecture's directory.
3. **Gate.** `scripts/gate-feed.sh` and `scripts/teeth-feed.sh` run before anything is pushed.
4. **Publish.** The `gh-pages` branch is replaced by one commit that holds only the feed, and
   GitHub Pages serves it. The script then waits until the published index is byte-identical to
   the one it built and runs `gate-feed.sh` again, against the published URL.

The packages are signed on one workstation, never in CI. A key held as a repository secret is
readable by anyone who can push a workflow, and this key cannot be revoked: a router that
trusts it keeps trusting anything signed with it until someone deletes the file from
`/etc/apk/keys`. The private half was made once, by `scripts/feed-keygen.sh`, and is never
committed; `TestNoPrivateKeyCommittable` fails if git would commit any private key.

## What the gate proves

`scripts/gate-feed.sh` installs from the feed in a clean `openwrt/rootfs` 25.12.6 container:

| check | what it requires |
| --- | --- |
| `check_refused_without_key` | with the feed added and no key, `apk update` names the feed as UNTRUSTED and `apk add rollcall` fails with `no such package` |
| `check_installs_with_key` | with the key, the feed's two packages become visible and `apk add rollcall luci-app-rollcall` succeeds |
| `check_no_allow_untrusted_needed` | no `--allow-untrusted` anywhere, `apk policy` names this feed as the source, and `rollcall version` runs |
| `check_files_owned_by_root` | every file both packages installed is owned by uid 0 and gid 0 |

`scripts/teeth-feed.sh` runs the gate four more times: on a copy re-signed with a throwaway key
that is published as the feed's key (it must pass), on the same copy with the real key in place
(it must fail `check_installs_with_key`), on a copy whose `rollcall` holds a file owned by
`nobody` (it must fail `check_files_owned_by_root`) and on no feed at all (it must say it
measured nothing).

## What has been run

On 2026-10-23, `publish-feed.sh` published v1.0.0-rc1 (apk version `1.0.0_rc1-r1`), taking the
packages from the `release-set` artifact of release.yml run 40008459032:

- all 8 `.apk` files and `SHA256SUMS` passed the checksum and attestation checks;
- every architecture's packages and index were signed and verified against keys/rollcall.pem
  only (`apk verify` with no other key);
- `gate-feed.sh` passed all 4 checks on the local copy and then on the published URL, in the
  `x86-64-25.12.6` root file system; it passed on the `aarch64_generic-25.12.6` one as well,
  for both copies;
- `teeth-feed.sh`: all 4 teeth held.

Not run yet: an install from this feed on a router. Every check above ran in a container.
