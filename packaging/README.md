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
| `/etc/hotplug.d/iface/50-rollcall` | forwards interface events to `rollcall notify iface` |
| `/etc/config/rollcall` | site configuration; kept across upgrades |
| `/etc/uci-defaults/90-rollcall` | firewall rule for UDP and TCP 7432 from each peer zone |
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

## Other status

- `capabilities/rollcall.json` follows the procd capability layout as understood at writing
  time. It is proven only when ICMP probes are enabled on hardware.
- uid and gid 1660 are unregistered; the postinst creates the account with them. Change them
  in `packaging/postinst` if they collide on a router.
- The state directory `/etc/rollcall` is owned by `rollcall` with mode 0700.
