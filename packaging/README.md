# Packaging

`packaging/files/` is the tree that lands on the router. `packaging/postinst` and
`packaging/prerm` are the lifecycle scripts. `packaging/seccomp/` holds the system call lists
and the generator that writes one profile per architecture. `scripts/mkipk.sh` and
`scripts/mkapk.sh` assemble the packages; `make release` drives them.

## What the package installs

| Path | Purpose |
|---|---|
| `/usr/bin/rollcalld`, `/usr/bin/rollcall` | daemon and CLI (built by the Makefile) |
| `/etc/init.d/rollcall` | procd service: user `rollcall`, `no_new_privs`, jail, control directory, and the snapshot written as root before each start; no procd seccomp profile (the daemon installs its own filter) |
| `/etc/hotplug.d/iface/50-rollcall` | forwards interface events to `rollcall notify iface` and writes the snapshot again (`rollcall snapshot`), both in the background |
| `/etc/hotplug.d/ntp/50-rollcall` | tells the daemon the clock is synchronised (`rollcall notify clock-synced`), in the background |
| `/etc/config/rollcall` | site configuration; kept across upgrades |
| `/etc/uci-defaults/90-rollcall` | builds the firewall rules at first boot and after an upgrade (`/etc/init.d/rollcall firewall`) |
| `/etc/seccomp/rollcall.json` | the system call allow-list of the target architecture in procd's format: the readable record of the filter rollcalld installs itself from the same lists; procd does not load it |
| `/etc/capabilities/rollcall.json` | `CAP_NET_RAW` in every set and nothing else, used only when `option icmp '1'` |
| `/etc/capabilities/rollcall-none.json` | all five sets present and empty, used on every start without ICMP probes, so the bounding set is empty too |
| `/lib/upgrade/keep.d/rollcall` | keeps `/etc/rollcall/` and `/etc/config/rollcall` on sysupgrade |

The package has no ubus ACL: the daemon never calls ubus.

## Every entry is owned by root

Every file and directory of both packages, in both formats, is owned by uid 0 and gid 0.
procd runs `/etc/init.d/rollcall` as root and hotplug runs `/usr/bin/rollcall` as root, and the
daemon binary (which carries its seccomp list), the capability file and the rpcd ACL decide the
sandbox, so an entry any other account owns would let that account replace it and gain root or
weaken the sandbox.

- `.ipk`: `mkipk.sh` writes every tar with `--numeric-owner --owner=0 --group=0` (GNU tar) or
  `--uid 0 --gid 0 --uname root --gname root` (bsdtar).
- `.apk`: `apk mkpkg` has no owner option. apk-tools 3.0.7 takes the uid and gid of each entry
  of the staged tree and names them from the passwd file of the system it runs on, writing
  `nobody` for an id it cannot name. A CI runner stages the tree as uid 1001, which the alpine
  image cannot name, so the first lab packages installed every file as nobody:nogroup.
  `mkapk.sh` now runs mkpkg on a copy of the tree owned by root (inside the container, so the
  runner can still delete its own tree) and reads the result back with `apk adbdump`: it fails
  unless every entry names user root and group root.

The gate `TestPackagesOwnedByRoot` (`internal/gates/packages_test.go`) reads the packages
`make release` wrote: every header of the three tars of each `.ipk`, and every acl of each
`.apk` as `apk adbdump` lists it. The CI job `packaging` runs it with `ROLLCALL_PACKAGES=1`, and
then plants a real `.apk` with a nobody-owned file and requires the gate to name it.

## Seccomp: the daemon installs its own filter

rollcalld installs its seccomp filter itself, at start. procd cannot do it for a statically
linked program: it applies the profile named by `procd_set_param seccomp` through
`LD_PRELOAD=/lib/libpreload-seccomp.so` and `SECCOMP_FILE`, and a static binary never loads a
preload library. The lab run of 2026-10-23 found the daemon on OpenWrt 25.12.5 (procd
2026.03.13~58eb263d with procd-seccomp and procd-ujail) at `Seccomp: 0`, and the daemon refused
to listen. The init script therefore no longer sets that parameter (`TestInitScriptHardening`
refuses it); procd and ujail still give the daemon its user, `no_new_privs` and the jail.

`main` calls `internal/sandbox` right after the command line, before the signal handler and
before anything opens a file or a socket (all of that is in `run`). It:

1. reads the lists of this directory, embedded in the binary (`packaging/seccomp/lists.go`), for
   its architecture, with the rules `generate.sh` uses;
2. numbers them with `golang.org/x/sys/unix` (`internal/sandbox/zsysnum_linux_*.go`, generated
   by `mksysnum.go`);
3. builds a classic BPF program: a call made with another audit architecture is killed, the
   listed numbers are allowed, and every other call kills the process (`SECCOMP_RET_KILL_PROCESS`);
4. sets `no_new_privs` and installs the program with
   `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC)`, so the kernel puts it on every
   thread the Go runtime already runs; a thread it cannot synchronise fails the install.

When any step fails on Linux the daemon logs `refusing to run without its seccomp filter` and
exits. Otherwise it logs `seccomp filter installed on every thread: N system calls of
linux/<arch> allowed`, and `sandboxGate` still refuses to listen unless the kernel reports
`NoNewPrivs: 1` and `Seccomp: 2`. The calls the Go runtime makes only before that point (its
start, package initialisation, the command line) are free of the filter.

`packaging/seccomp/generate.sh <openwrt-arch>` writes the same names as the profile the package
installs as `/etc/seccomp/rollcall.json`, the readable record of the filter. It is `common.txt`
plus the list of the architecture's family, sorted, with no duplicates:

| List | Applies to | Holds |
|---|---|---|
| `common.txt` | every target | names that exist on aarch64, amd64, arm and mips |
| `amd64.txt` | `x86_64` | `arch_prctl` (Go sets the TLS base with it, also for every new thread), `mmap`, `newfstatat` |
| `aarch64.txt` | `aarch64_*` | `mmap`, `newfstatat`; no 32-bit legacy names, no `arch_prctl` |
| `arm.txt` | `arm_*` | the EABI names: `mmap2` (EABI has no `mmap`), `brk`, `open`, `futex_time64`, `fstat64`, `fstatat64`, the 32-bit uid calls, ... |
| `mips.txt` | `mips_*`, `mipsel_*` | the o32 names: `mmap`, `mmap2`, `brk`, `open`, `futex_time64`, `stat64`, `lstat64`, `fstat64`, `fstatat64`, ... (o32 has no `newfstatat`) |

Every profile uses `defaultAction` `SCMP_ACT_KILL_PROCESS`. The gates in
`internal/gates/seccomp_test.go` and `internal/gates/sandbox_test.go`:

- `TestSeccompProfilesPerArch`: every generated profile parses, kills by default, carries
  `arch_prctl` only on amd64, no 32-bit legacy name on aarch64, and neither `execve` nor
  `execveat`.
- `TestSeccompRuntimeSetPerArch`: it carries the named set of calls the Go 1.27 runtime, the
  standard library and the daemon make, each listed with the source that makes it (for example
  `prctl` from `runtime/set_vma_name_linux.go`, `eventfd2` from `runtime/netpoll_epoll.go`, and
  on 32-bit `futex_time64` from `runtime/os_linux32.go`).
- `TestSeccompNamesExistPerArch`: every name is a system call of that architecture as
  `golang.org/x/sys/unix` numbers it, so a name that protects nothing there (`newfstatat` on
  mips, `mmap` on arm) cannot stand in for the call the daemon really makes.
- `TestSeccompDaemonListIsTheProfile`: for every shipped target, the names the daemon's filter
  allows are exactly the names of the profile the package ships.
- `TestDaemonConfinesFirst`: `main` installs the filter before any call other than the command
  line and the log flags, and exits when it cannot.

One entry is allowed on reasoning rather than a Go source: `restart_syscall`, through which the
kernel resumes a sleep a signal interrupted (Go's preemption signal interrupts them). `execve` is
not allowed: the filter goes on after the daemon was started, and the daemon never runs a
program. Some names are made only at the runtime's start on some kernels (`brk` and `open` on
32-bit, `prctl` where the kernel does not name anonymous mappings) and are kept, because the
runtime may make them again later.

Proof that runs: the CI job `seccomp` runs `go test ./internal/sandbox` on amd64 and arm64
kernels, which re-executes a child that installs the filter and calls `getppid` (in no list): it
must die by SIGSYS, on the main thread and on a second thread that existed before the install
(TSYNC), while a child that makes a listed call lives and shows `NoNewPrivs: 1` and
`Seccomp: 2`. Then `tools/seccomp-run/prove.sh` builds rollcalld for amd64 and arm64, starts it
directly with no loader, and requires: its own filter in force on every thread (one filter more
than the harness) and its log naming as many calls as its list; the control socket served, UDP
and TCP 7432 bound, a group made with `rollcall init` and the node started, a heartbeat routed
(rtnetlink route lookup) to a static peer, discovery on the default-route device, 30 s alive and
a clean stop. Last, daemons built from a copy of the tree whose list lacks `prctl`, `eventfd2` or
`epoll_pwait` must log one call fewer and die by SIGSYS within 20 s (run with `GOGC=off` and
driven by status calls, so the heap grows). `prctl` is shown only where the kernel names
anonymous mappings (`CONFIG_ANON_VMA_NAME`); elsewhere the runtime stops calling it at its first
refusal, before the filter is on, and the job says so. It tries linux/arm on the arm64 runner too
and reports NOT RUN when that CPU or kernel does not execute AArch32. Not proven by CI: mips (no
runner), the daemon under procd and ujail on a router (the lab run), and code paths the CI run
does not reach (Telegram and ntfy delivery, ICMP probes).

## Control directory and socket

The init script creates `/var/run/rollcall` as rollcall:rollcall with mode 0700 before the jail
is built, and mounts it read-write into the jail. The daemon creates the control socket in it.

Shared constants, named the same in Go (Task 21, used by `cmd/rollcall` and `cmd/rollcalld`):

- `ControlDirPath` = `/var/run/rollcall`
- `ControlSocketPath` = `/var/run/rollcall/control.sock`

Why rollcall:rollcall 0700: the daemon runs as `rollcall` and must create the socket, and
`internal/control` refuses a socket directory that group or others may write to unless the
sticky bit is set (a writer could swap the socket for a link). The earlier root:rollcall 0770
failed that check, so every start was refused. Root runs the CLI from hotplug, the init script
and LuCI, and reaches the socket whatever the directory mode, because root bypasses file
permissions. The gate `TestInitScriptHardening` applies the control rule to the mode and owner
the init script sets, and reads the path from `ControlDirPath` in `cmd/rollcalld/main.go`.

## Firewall

One builder writes the rules: `/etc/init.d/rollcall firewall`. The postinst and
`uci-defaults/90-rollcall` run it at install, and `reload_service` runs it again whenever the
rollcall or firewall configuration changes (`procd_add_reload_trigger rollcall firewall`), then
reloads the firewall and restarts the daemon when `/etc/config/rollcall` or the snapshot changed
(`procd_set_param file`). It reads the configuration through `uci` alone and removes every rule
an earlier run wrote (`firewall.rollcall_N`, and `firewall.rollcall` of earlier versions).

- One rule per peer zone, `src` = that zone (fw4 takes one zone per rule), UDP and TCP to
  `option port` (default 7432). No `peer_zone` means `lan`, the daemon's default.
- A zone faces the internet when `masq` or `masq6` is set to anything but an off value, or when
  the zone is or holds the network `wan`, `wan6` or `wwan`. `internal/config` decides the same
  and accepts such a zone only together with static peers. Its rule admits only the static
  peers' addresses (`src_ip`), one rule per address family (`family ipv4` / `ipv6`), so a mixed
  list never depends on how fw4 splits families. Static peers are IP literals (`IP`, `IP:port`,
  `[IPv6]:port`; host names are refused by the daemon), so `src_ip` is the address itself,
  without the port and without the zone of a link-local address.
- Such a zone without a static peer, a zone the firewall does not have, a bad port or no
  rollcall section get no rule at all, and the builder says why on stderr and in syslog.

The gate `TestFirewallRuleBuilder` runs the builder against a stub `uci` (19 cases) and its
teeth plant the faults the first builder had: the literal port 7432, a zone facing the internet
opened to every source, and `src_ip` dropped.

## Hotplug

netifd and ntpd wait for their hotplug scripts, so the scripts never wait for the daemon: the
CLI runs in the background with its input and output on `/dev/null` (so hotplug's own pipe
closes at once), under `timeout 5` where busybox has the applet, and the CLI keeps its own 10 s
limit on every control command. The gate `TestHotplugNeverBlocks` requires every CLI call in
`files/etc/hotplug.d` to be backgrounded and detached. The cost, named: two events for one
interface a few milliseconds apart may reach the daemon in the opposite order.

## Jail

`procd_add_jail rollcall log procfs sysfs ronly requirejail`: `requirejail` makes procd refuse
to start the daemon without the jail, and `ronly` remounts the jail's root read-only (`ujail -o`),
so the only writable paths are the `procd_add_jail_mount_rw` ones: `/etc/rollcall`,
`/var/run/rollcalld` and `/var/run/rollcall`. Read-only, the jail carries `/etc/config/rollcall`,
`/etc/openwrt_release`, `/etc/ssl/certs`, `/usr/share/zoneinfo` and the three resolver paths
below, and never `/etc/config/network`, `/etc/config/system` or `/etc/config/firewall`, nor a
directory holding them (next section). The gate `TestInitScriptHardening` refuses a jail mount
that is or holds one of them. The word `ronly` is the one `_procd_add_jail` in
OpenWrt's `procd.sh` accepts (read on openwrt/openwrt main, 2026-10-23); that the root is in fact
read-only is proven only by the lab run, by a write outside those paths failing inside the jail.

DNS inside the jail: on OpenWrt 24.10 and 25.12 `/etc/resolv.conf` links to `/tmp/resolv.conf`,
which `/etc/init.d/boot` links to `/tmp/resolv.conf.d/resolv.conf.auto` and dnsmasq may replace
with its own file (`nameserver 127.0.0.1`). The init script mounts all three read-only. procd's
ujail binds a path by following its links (`stat`, then a bind mount of the target), so the
jail's `/etc/resolv.conf` is the file present when the daemon starts; ujail also adds
`/etc/resolv.conf` by itself when the jail has no network namespace, and accepts the same mount
listed twice (procd `jail/fs.c` and `jail/jail.c`, read on openwrt/procd master, 2026-10-23).
With dnsmasq the file names 127.0.0.1 and stays right; on a router without dnsmasq, a change of
the upstream DNS servers reaches the daemon at its next start. Proven only by the lab run:
a Telegram message or a probe by host name from inside the jail.

## The snapshot: what the daemon takes from network, firewall and system

On OpenWrt 25.12 `/etc/config/network` and `/etc/config/system` are mode 0600 root: network may
hold PPPoE passwords and WireGuard private keys. The daemon runs as `rollcall` and may not read
them, so it never does. Root parses them with the daemon's own parser (`internal/config`) and
writes only what the daemon uses to `/var/run/rollcall/snapshot.json`:

| Field | From | Used for |
|---|---|---|
| `zones[].name`, `zones[].devices` | firewall zones (`network`, `device`) and the network interfaces they name | the devices the daemon listens on, and the check that each peer zone exists and has a device |
| `zones[].external` | firewall `masq`, `masq6`, and the networks `wan`, `wan6`, `wwan` | refusing a zone that faces the internet without static peers |
| `tz`, `tz_source` | system `zonename` (UTC when there is none) | the times in messages and status |
| `sources` | the size and modification time of network and system, the SHA-256 of firewall | refusing a snapshot older than those files |

Nothing else of those files reaches it: no option value of network but device names, and no
hostname (the CLI takes the router name from the kernel). A zone whose name is outside
`[A-Za-z0-9_-]` is left out, as the firewall rule builder gives it no rule. `/etc/config/rollcall`
holds no secret (the parser refuses any option it does not know, and the ntfy URL may carry no
user, password or query) and stays mode 0644, read by the daemon itself.

- Written by `rollcall snapshot`, as root: by the init script before every start (and so at
  `reload_service`), and by the interface hotplug on every event, so a daemon procd respawns
  after a network change reads the facts as they are. It parses the three files, writes a new
  file beside the old one with `O_EXCL` (a link planted in the directory is never followed),
  sets mode 0640 and owner root with the directory's group (rollcall), syncs and renames it over
  the old one. It refuses a run directory that is a link. When the files cannot be described, it
  removes the old snapshot, so the daemon refuses to start rather than run on stale facts. A
  line of network or system it cannot parse is reported by its number, never its text.
- Why root:rollcall 0640 and not rollcall-owned 0600: the facts are root's statement about files
  the daemon may not read, so root keeps the file; the group bit lets the daemon read it and
  nobody else. The directory is the daemon's (it creates the control socket there), so the
  daemon could still replace the file; that gains it nothing it did not have, and the CLI never
  follows anything it could plant.
- Read by `rollcalld -snapshot` (default `/var/run/rollcall/snapshot.json`) before anything
  else: a regular file, not writable by group or others, at most 64 KiB, one JSON object with
  no unknown field, version 1, at most 32 zones of at most 64 devices, every zone name, device
  name and the time zone checked, zones and devices in strict order. Missing, malformed or stale,
  the daemon logs `refusing to start without a current snapshot ...` and exits; it never falls
  back to the files.
- Stale: the daemon refuses a snapshot when network or system has another size or time, the
  firewall file other content, or a missing system file appeared. Inside the jail the daemon
  sees none of the three, so it cannot compare there: freshness on a router rests on the root
  side writing the snapshot before each start, at each reload and on each interface event. A
  change of the time zone alone (`/etc/init.d/system reload`) reaches the snapshot at the next
  start, reload or interface event.
- Proof that runs: the CI job `seccomp` makes network and system root's with mode 0600 (network
  holding a password), has root write the snapshot, and runs the daemon as an unprivileged user
  under its own seccomp filter; before this change the daemon stopped there with `open
  .../network: permission denied`, as on the lab routers. Not proven until the next lab run: the
  snapshot written by procd's init script on a router, and the daemon inside ujail reading it.

## Other status

- The capability files follow the layout ujail reads (`jail/capabilities.c` of procd
  2026.03.13~58eb263d, the procd of OpenWrt 25.12): the arrays `bounding`, `effective`,
  `inheritable`, `permitted` and `ambient`. Each listed set becomes exactly its names; an absent
  set is left with every capability, and without a file ujail sets none, so the setuid to
  `rollcall` empties the other sets but leaves the bounding set full (lab run 2026-10-23:
  `CapBnd 000001ffffffffff`). Hence a file on every start, with all five sets named. The gate
  `TestInitScriptHardening` reads both files and both package scripts. Not proven until the next
  lab run: `CapBnd 0000000000000000` on a router, and `rollcall.json` with ICMP probes on.
- rollcalld cannot empty its bounding set itself: `PR_CAPBSET_DROP` needs `CAP_SETPCAP` in the
  effective set, and the daemon runs with none.
- uid and gid 1660 are unregistered; the postinst creates the account with them. Change them
  in `packaging/postinst` if they collide on a router.
- The state directory `/etc/rollcall` is owned by `rollcall` with mode 0700.
