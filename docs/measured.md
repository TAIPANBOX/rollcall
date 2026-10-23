# Measured

What was run, where and when, and what it printed. A claim that is not in this file has not been
run; the [list at the end](#not-yet) names what is still open.

## The lab run, 2026-10-23

Three routers on vanilla **OpenWrt 25.12.5**, all `aarch64_cortex-a53`: a GL.iNet Flint 2 named
`flint2` and two Beryl AX named `beryl1` and `beryl2`. The packages came from the CI job
`lab-packages` (version `0.0.0-rc67`, commit `4186091`) and were installed by hand. On that day all
three routers sat on one LAN segment, with their WAN ports unused and their radios off.

Roles: `flint2` primary admin and sender, `beryl1` backup admin, `beryl2` an ordinary member.

| Step | What happened |
|---|---|
| install | `apk add` of `rollcall` and `luci-app-rollcall` on all three; every package file owned by root (checked on the reinstall after fix 1 below) |
| `rollcall init` on flint2 | group `home` created; the recovery code printed once, kept in a private file for the run and deleted at its end |
| `rollcall invite` and `rollcall join`, twice | beryl1 and beryl2 joined; the join code was piped from one router to the other and never printed; the group key rotated at the second join |
| `rollcall roles` | beryl1 backup admin, flint2 sender |
| `rollcall set-token` on flint2 | the token went in through the environment; afterwards `logread` held 0 token-shaped strings |
| `rollcall bind-telegram` | the chat was bound with one code sent from a phone; the four roster announcements held while no chat was bound arrived together |
| internet cut on flint2 | default route removed at 18:06:57, put back at 18:09:57: one message |
| forced reboot of beryl2, no clean shutdown | one message, back after 44 s |
| clean reboot of flint2 at 18:16:16 | one message at 18:17, back after 45 s |
| removal | `apk del`, then the state directory, the configuration, the user and the group: no file left, no firewall rule, no user, port 7432 closed |

### The sandbox, read from `/proc` on each router

![The sandbox: jail, user, no_new_privs, the daemon's own seccomp filter, and the snapshot that replaces the root-only configuration files](sandbox.svg)

The three routers printed the same values:

- `NoNewPrivs: 1`, `Seccomp: 2`, `Seccomp_filters: 1`. The one filter is the daemon's own: procd
  installs none.
- `Seccomp: 2` on every thread: 10 threads on flint2, 8 on each Beryl AX.
- The log line `seccomp filter installed on every thread: 74 system calls of linux/arm64 allowed,
  any other ends the process`. The profile the package ships lists the same 74.
- `Uid` and `Gid` 1660, the `rollcall` account.
- `CapInh`, `CapPrm`, `CapEff` and `CapAmb` all 0. `CapBnd` was still the full set
  (`000001ffffffffff`); see [Not yet](#not-yet).
- The jail's root holds `dev etc proc sys tmp usr var`, not the router's own root.
- `listening on port 7432 on br-lan; SO_BINDTODEVICE applied: true`.

### The chat

![The three chat lines of the lab run](chat.svg)

The lines as the chat received them, one per incident:

```text
home: internet was down from 18:07 to 18:10 (3 min), confirmed by 0 of 2. Seen by flint2. Times are approximate.
home: beryl2 rebooted unexpectedly at 18:11, back after 44 s, confirmed by 0 of 2. Times are approximate.
home: flint2 rebooted as planned at 18:16, back after 45 s, confirmed by 1 of 2.
```

What they show, and what they do not:

- **One message per incident.** The start of the internet outage was merged into the incident and
  not sent on its own. The forced reboot was one message, not "stopped answering" and then "back".
- **A planned reboot and a crash read differently.** flint2 announced its shutdown; beryl2 did not.
- **"Times are approximate"** on the first two lines: the daemons had started after the router
  clocks were set, and nothing told them so. After flint2's reboot the clock event came with the
  boot, and its line carries no such note.
- **"confirmed by 0 of 2"** on beryl2's reboot read as if no router confirmed it, although flint2
  and beryl1 both saw beryl2 go silent: the count took only signed statements about the earliest
  record, and those are made only on a trusted clock. After the lab run the count was changed to
  the routers that recorded the absence or agreed with it when the message is made, and an
  internet or WAN loss, which is one router's own event, carries no count. In the tests the lab's
  lines now read "confirmed by 2 of 2"; this has not run on the routers yet.

The wording is that day's. It may change before a release.

### Found during the run and fixed before its end

Each fix has a test or a gate that failed on the old code.

1. **Package files owned by nobody.** apk-tools 3.0.7 names the owners of a package from the
   staged tree, and the CI runner's uid was unknown in the build image, so every file installed as
   `nobody:nogroup`. `scripts/mkapk.sh` now packs a root-owned copy and reads the package back; the
   gate `TestPackagesOwnedByRoot` checks every entry, and CI plants a nobody-owned file to prove the
   gate fails on it.
2. **Root-only configuration.** `/etc/config/network` and `system` are mode 0600 root on 25.12.5
   and can hold PPPoE passwords and WireGuard keys. The daemon may not read them, so root now writes
   a snapshot of the few facts it needs (`rollcall snapshot`), and the daemon reads only that.
3. **A directory under `/tmp` prepared as root.** The run directory moved to `/var/run`, and a gate
   refuses `mkdir`, `chown` or `chmod` under `/tmp` in the init script.
4. **procd cannot filter a static program.** procd applies a seccomp profile through
   `LD_PRELOAD`, which a statically linked Go binary never loads: the daemon read `Seccomp: 0` and
   refused to listen. It now installs its own filter at start ([packaging/README.md](../packaging/README.md#seccomp-the-daemon-installs-its-own-filter)).

### Two traps for whoever runs the steps

- A rollback timer started with `nohup ... &` over SSH died with the session, and the route stayed
  removed for about 20 s with no timer behind it. A timer started with `start-stop-daemon -b`
  survived and was checked from a new session.
- A helper function that reused a shell variable sent one `join` to the wrong router. That router
  refused it, as it should.

Skipped that day: sysupgrade, a mesh, NAT, and the replay and flood checks from a laptop on the LAN.
A baseline of the flash write counters was taken at 18:18; no soak followed, so there is no figure.

## CI

Run `39990683889`, the push of commit `4186091` on 2026-10-23. Every job passed:

- **gates**: `gofmt`, `go vet`, `go mod verify`, a build with the release flags, `go test -race`
  with a coverage profile, the 200-seed simulator sweep, the coverage floor, `govulncheck`.
- **reproducible**: two `linux/arm64` builds with separate caches, byte-identical.
- **packaging**: the `x86_64` release set, what the `.ipk` and the `.apk` contain, every entry owned
  by root, and the planted nobody-owned file caught.
- **seccomp**, three legs. `rollcalld` was started with no loader and ran under its own filter on
  every thread: `x86_64` (75 calls), `aarch64_cortex-a53` (74) and `arm_cortex-a7` (87, run on the
  arm64 runner). Each served its control socket, bound UDP and TCP 7432, made a group, ran discovery
  for 30 s and stopped cleanly. Daemons built with one call left out of the list (`prctl`,
  `eventfd2`, `epoll_pwait`, and `futex_time64` on arm) were killed by SIGSYS.

CI has no MIPS runner. A mutation job (gremlins) runs on manual runs and tags; it reports scores and
does not gate.

## Tests on a workstation

`go test ./... -count=1` on 2026-10-23 at 18:44 BST, commit `80c38d8`, Go 1.27.3 on darwin/arm64:
31 packages passed, none failed, two have no tests. The same run with `-json` counted 848 top-level
tests passed, 0 failed, 4 skipped, and 867 subtests passed. The four skips: two gates that read what
CI prepares (`ROLLCALL_COVERAGE`, `ROLLCALL_PACKAGES`), the ICMP probe (it needs a raw socket), and
one link-local test that does not apply to macOS's loopback.

Coverage, `go test -cover ./internal/...` on the same commit: from 90.4% (`internal/node`) to
100% per package; every statement of `internal/...` together, 94.3%
(`go test -coverprofile=internal.out ./internal/... && go tool cover -func=internal.out`). On macOS
the code that installs the seccomp filter does not run; the CI legs above run it. The CI gate keeps
coverage from falling below `coverage-baseline.txt`, which still holds 0.0, so it holds no real
floor yet.

## Not yet

- **Flash wear over days.** Only a baseline was taken.
- **MIPS on hardware**, and every target but `aarch64_cortex-a53` on a router. arm and x86_64 ran in
  CI only.
- **OpenWrt 24.10 and the `.ipk`.** Built, never installed on a router.
- **Mesh, separate LANs with their own DHCP, routed segments, NAT.** The lab routers shared one
  LAN; the other topologies ran in the in-process simulator only.
- **sysupgrade.** Not run, so whether a clean shutdown is announced during one is not known.
- **A pulled power cord and an unplugged WAN cable.** The lab forced a reboot and removed a route
  instead.
- **Replay and flood from a device on the LAN.** The tools are in `tools/`; unit tests and the
  simulator cover forged and replayed packets, the lab did not run them.
- **The LuCI pages on a router.** The package installed; its pages and its rpcd rules were not used.
- **ICMP probes** (off by default) and the capability they add.
- **An empty capability bounding set on a router.** It was full on the lab day. With
  `no_new_privs` and no `execve` in the filter the daemon cannot use it. Since the run, every start
  names a capabilities file, so the set is empty unless ICMP is on; that has not run on a router.
- **Clock trust after a daemon restart on a router.** Since the run, the ntp hotplug script also
  takes the periodic event of a synchronised clock; that has not run on a router.
- **The confirmation count**, above: open.
- **A signed package feed, and a release.** Neither exists.
