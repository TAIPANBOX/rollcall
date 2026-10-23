# Contributing

Pull requests are welcome: a fix, a router we have not tried, a clearer page. This file says how to
build and test what CI builds and tests, and what a pull request is held to before it is merged.

A security problem goes through [SECURITY.md](SECURITY.md), not a pull request or an issue.

## The flow

1. Fork the repository and branch from `main`.
2. Make the change, with its scenario and its test (see [What a pull request is held to](#what-a-pull-request-is-held-to)).
3. Run the checks that cover it locally, then open a pull request against `main`.
4. CI runs on the pull request: the gates and tests, two byte-identical arm64 builds, the packages,
   and the daemon under its own seccomp filter on x86_64, aarch64 and arm.
5. A maintainer reviews and merges.

## Building and testing locally

You need Go at the version in `go.mod` (1.27). These are the commands CI runs, in its order:

```sh
gofmt -l .                                   # prints nothing
go vet ./...
go mod verify
go test -race -coverprofile=coverage.out ./...
ROLLCALL_SEEDS=200 go test ./internal/sim/ -run TestSweep -timeout 15m
ROLLCALL_COVERAGE=1 go test ./internal/gates -run TestCoverageNotBelowBaseline -v
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

The sweep runs the in-process simulator. Each seed builds a site of 3 to 5 routers on a fake network
with a fake clock, one of which shows different histories to different routers, and puts it through
four and a half minutes of random faults: power cuts, reboots, upgrades, partitions, lost links,
internet and Telegram outages, packet loss and delay. After everything heals it checks, among other
things, that every power cycle reached the chat, that nothing was sent twice without a partition,
that the lying router is caught with proof, and that no honest router is accused. The list of known
defects the sweep may excuse (`internal/sim/defects_test.go`) is empty.

The packages need Docker as well, because the `.apk` is written by apk-tools from a pinned Alpine
image:

```sh
make release VERSION=0.0.0-test TARGETS=x86_64          # what the packaging job builds
make apk luci VERSION=0.0.0-rc1 TARGETS=aarch64_cortex-a53   # what a test router installs
```

`go test ./internal/sandbox` installs a real seccomp filter in a child process and needs a Linux
kernel; on a Mac, run it in a Linux container. CI runs it on amd64 and arm64, and
`tools/seccomp-run/prove.sh` starts the daemon itself under its filter. Neither covers MIPS, which
has no runner.

## The gates

`internal/gates` holds the repository's own checks: only `golang.org/x/crypto` and
`golang.org/x/sys` beside the standard library; no `os/exec` in the daemon; no
`InsecureSkipVerify`; every scenario bound to a test; the init script's user, `no_new_privs` and
jail; no HTML sink in the LuCI app; the seccomp list of each architecture, and the daemon's filter
equal to the profile the package ships; the firewall rule builder; hotplug that never blocks;
package files owned by root; the coverage floor.

`scripts/gates-have-teeth.sh` plants each gate's own fault and requires the gate to fail on it, to
pass on a clean copy, and to say "measured nothing" when its subject is gone. A new gate adds its
case from its own file, with `func init() { toothCases = append(toothCases, ...) }`.

## What a pull request is held to

1. **New behaviour has a scenario.** It goes in `features/*.feature`, in plain words, with an
   `@test:<TestName>` tag naming the test that proves it. `TestFeatureBindings` fails on a scenario
   without a test and on a tag that names no test.
2. **A new test fails first.** Run it against the code before your change, and put the command and
   the failure in the pull request. A test that has never failed proves nothing.
3. **A new gate has teeth**, as above.
4. **No new dependency.** The standard library, `golang.org/x/crypto` and `golang.org/x/sys` only;
   the gate fails on any other module.
5. **No secret anywhere it can be read.** Tokens, keys and codes stay out of logs, status output,
   command lines and UCI. Tests use made-up values such as `CANARY-123:abc`.
6. **Coverage does not fall.** The number and its change go in the pull request, with the paths
   that matter and are still not covered.

A pull request that only changes documentation needs `gofmt`, the features gate and a reader.

## Changes to cryptography, membership or delivery

Some parts decide silently. If they are wrong, nothing fails where anyone can see it: an alert is
just never sent, or a device that is not a member gets in. Those parts are packet authentication and
replay (`internal/wire`, `internal/replay`, `internal/sig`, `internal/epoch`), the roster, pairing
and admin authority (`internal/roster`, `internal/pairing`), the history chains (`internal/history`),
the choice of sender and delivery (`internal/elect`, `internal/deliver`), and `internal/node`, which
ties them together. A change there is held to more:

- **A reviewer reads the whole change**, not only its tests.
- **Mutation testing.** Break the logic on purpose, in the way a wrong answer would stay silent, and
  show that an existing or new test catches it. Name each mutant and the test that caught it in the
  pull request. CI also runs gremlins over these packages on manual runs and tags; it reports scores
  and does not gate.
- **The invariants stay true.** Section 12 of
  [the security architecture](docs/superpowers/specs/2026-10-22-rollcall-security.md) lists them. A
  change that alters one updates the spec and its gate in the same pull request.
- **No new primitive.** Cryptography comes from the Go standard library and `golang.org/x/crypto`.

## If you ran it on a router

Say which router, `cat /etc/apk/arch`, `cat /etc/openwrt_release`, the package version or commit,
and what you ran. Before pasting a log, look for tokens and codes in it.

## Releases

There is no release yet, and no package feed. The release workflow runs only on a tag: it tests,
builds every target twice and requires the two builds to be byte-identical, packages them, writes an
SBOM per binary and a `SHA256SUMS`, attests every file and publishes a GitHub release.

## License

The repository is under the [MIT License](LICENSE). A contribution is accepted under the same
license.
