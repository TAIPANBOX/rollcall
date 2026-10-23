# Security

rollcall runs on routers, listens on the LAN, signs and checks every message the routers exchange,
and keeps a Telegram bot token on the routers that send. A flaw in that path matters more than most
bugs, so please report it privately.

## Reporting a vulnerability

Use GitHub's private report:
[Report a vulnerability](https://github.com/TAIPANBOX/rollcall/security/advisories/new).
Do not open a public issue or pull request for it.

Please include:

- what you did and what happened, with the commands, so it can be reproduced;
- the router's architecture (`cat /etc/apk/arch`) and OpenWrt version (`cat /etc/openwrt_release`);
- the package version (`apk list --installed | grep rollcall`) or the commit you built;
- for anything about the group, `rollcall status --json` (it holds no secret; change the router
  names if you like).

Never send a real bot token, join code, bind code or recovery code. A made-up one shows the problem
just as well.

rollcall has not been released, so there are no supported versions yet. A fix lands on `main`, and
the advisory is published once the fix is there.

## In scope

- the daemon `rollcalld`, the CLI `rollcall`, and the packages this repository builds (`rollcall`,
  `luci-app-rollcall`) with their init, hotplug and firewall scripts;
- the protocol: anything that lets a device that is not a member inject, replay or suppress an
  event, read the group's traffic or join without a join code; a member that can speak as another
  member; a removed router that can still read or send;
- the roster and the history: a roster accepted without an admin signature or rolled back, a
  takeover accepted while the primary admin is still heard, a rewritten history that goes unnoticed;
- the sandbox: anything the daemon can do outside its user, its seccomp filter or its jail, any read
  of `/etc/config/network` or `system` by the daemon, and anything a less privileged account can
  plant for a script that runs as root;
- secrets: the bot token, a key, or a join, bind or recovery code reaching a log, the status output,
  LuCI, a command line, or a router without the sender role;
- the Telegram path: certificate checks turned off, markup or links reaching a message, the chat
  binding taken by another chat.

## Not a vulnerability here

The security design lists the risks that are known and accepted, in section 13 of
[the security architecture](docs/superpowers/specs/2026-10-22-rollcall-security.md). Among them: a
member that is fully compromised can lie about itself until it is removed, and a sender's token can
be used until it is revoked in @BotFather; system backup files hold rollcall's secrets; Telegram
sees router names and outage times; a flood can make routers look silent, which is reported rather
than hidden. A way past one of those that the design does not describe is still worth reporting.

A flaw in OpenWrt, procd, ujail or Go itself belongs upstream.
