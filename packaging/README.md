# Packaging

`packaging/files/` is the tree that lands on the router. `packaging/postinst` and
`packaging/prerm` are the lifecycle scripts. `scripts/mkipk.sh` and `scripts/mkapk.sh`
assemble the packages from this tree and the two binaries; `make release` drives them.

## What the package installs

| Path | Purpose |
|---|---|
| `/usr/bin/rollcalld`, `/usr/bin/rollcall` | daemon and CLI (built by the Makefile) |
| `/etc/init.d/rollcall` | procd service: user `rollcall`, `no_new_privs`, seccomp, jail |
| `/etc/hotplug.d/iface/50-rollcall` | forwards interface events to `rollcall notify iface` |
| `/etc/config/rollcall` | site configuration; kept across upgrades |
| `/etc/uci-defaults/90-rollcall` | firewall rule for UDP and TCP 7432 from each peer zone |
| `/etc/seccomp/rollcall.json` | system call allow-list for the daemon |
| `/etc/capabilities/rollcall.json` | `CAP_NET_RAW`, used only when `option icmp '1'` |
| `/lib/upgrade/keep.d/rollcall` | keeps `/etc/rollcall/` and `/etc/config/rollcall` on sysupgrade |

The package has no ubus ACL: the daemon never calls ubus.

## Status of the sandbox files

- `seccomp/rollcall.json` is an allow-list written by hand. It is proven only in the lab
  (Task 27, aarch64 hardware). If the daemon is killed by seccomp, extend the list there
  and record which call was missing. The 32-bit legacy names (`mmap2`, `fstat64` and so on)
  are for arm and mips and are not yet proven on those targets.
- procd's handling of a name that does not exist on the running architecture is not yet
  verified. Task 27 must confirm that the profile loads on aarch64 (`Seccomp: 2` in
  `/proc/<pid>/status`).
- `capabilities/rollcall.json` follows the procd capability layout as understood at writing
  time. It is proven only when ICMP probes are enabled on hardware.

## Account and state

The postinst creates group and user `rollcall` with uid and gid 1660. No registry assigns
that number; change it in `packaging/postinst` if it collides on a router. The state
directory `/etc/rollcall` is owned by `rollcall` with mode 0700.
