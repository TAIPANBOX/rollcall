# Packaging

`packaging/files/` is the tree that lands on the router. `packaging/postinst` and
`packaging/prerm` are the lifecycle scripts. `packaging/seccomp/` holds the system call lists
and the generator that writes one profile per architecture. `scripts/mkipk.sh` and
`scripts/mkapk.sh` assemble the packages; `make release` drives them.

## What the package installs

| Path | Purpose |
|---|---|
| `/usr/bin/rollcalld`, `/usr/bin/rollcall` | daemon and CLI (built by the Makefile) |
| `/etc/init.d/rollcall` | procd service: user `rollcall`, `no_new_privs`, seccomp, jail, control directory |
| `/etc/hotplug.d/iface/50-rollcall` | forwards interface events to `rollcall notify iface`, in the background |
| `/etc/hotplug.d/ntp/50-rollcall` | tells the daemon the clock is synchronised (`rollcall notify clock-synced`), in the background |
| `/etc/config/rollcall` | site configuration; kept across upgrades |
| `/etc/uci-defaults/90-rollcall` | builds the firewall rules at first boot and after an upgrade (`/etc/init.d/rollcall firewall`) |
| `/etc/seccomp/rollcall.json` | system call allow-list, generated for the target architecture |
| `/etc/capabilities/rollcall.json` | `CAP_NET_RAW`, used only when `option icmp '1'` |
| `/lib/upgrade/keep.d/rollcall` | keeps `/etc/rollcall/` and `/etc/config/rollcall` on sysupgrade |

The package has no ubus ACL: the daemon never calls ubus.

## Seccomp: one profile per architecture

`packaging/seccomp/generate.sh <openwrt-arch>` writes the profile on stdout. It is
`common.txt` plus the list of the architecture's family, sorted, with no duplicates:

| List | Applies to | Holds |
|---|---|---|
| `common.txt` | every target | names that exist on aarch64, amd64, arm and mips |
| `amd64.txt` | `x86_64` | `arch_prctl` (Go sets the TLS base with it), `newfstatat` |
| `aarch64.txt` | `aarch64_*` | `newfstatat`; no 32-bit legacy names, no `arch_prctl` |
| `arm.txt` | `arm_*` | the 32-bit legacy names (`mmap2`, `fstat64`, `fstatat64`, `_llseek`, ...) |
| `mips.txt` | `mips_*`, `mipsel_*` | the o32 legacy names |

Every profile uses `defaultAction` `SCMP_ACT_KILL_PROCESS`. The gate
`TestSeccompProfilesPerArch` (`internal/gates/seccomp_test.go`) runs the generator for every
shipped target and checks that each output parses, kills by default, carries `arch_prctl`
only on amd64 and carries no 32-bit legacy name on aarch64.

Status: only the aarch64 profile is proven, and only in the lab (Task 27): the daemon must run
with `Seccomp: 2` in `/proc/<pid>/status`. If the daemon is killed by seccomp, extend the list
there and record which call was missing. The arm and mips lists come from the ABI tables, not
from hardware. procd's handling of a name that does not exist on the running architecture is
not verified; the per-family split exists so that it never has to be.

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
reloads the firewall and restarts the daemon when one of its configuration files changed
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
`/tmp/rollcall` and `/var/run/rollcall`. The word `ronly` is the one `_procd_add_jail` in
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

## Other status

- `capabilities/rollcall.json` follows the procd capability layout as understood at writing
  time. It is proven only when ICMP probes are enabled on hardware.
- uid and gid 1660 are unregistered; the postinst creates the account with them. Change them
  in `packaging/postinst` if they collide on a router.
- The state directory `/etc/rollcall` is owned by `rollcall` with mode 0700.
