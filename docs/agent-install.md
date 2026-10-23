# Installing rollcall: a runbook for agents

This file is for an AI agent that installs or operates rollcall on OpenWrt routers over SSH. A
person wants the [README](../README.md); the commands are the same.

Rules for this file: run each step's commands, then its **check**, and go on only when the check
prints what **expect** says. On anything else, stop and report the step, the command and its full
output to the person you work for, with any token or code taken out. Never improvise around a
failed check.

rollcall 1.0.0-rc1 is a release candidate. Its packages for OpenWrt 25.12 come from a signed apk
feed ([feed.md](feed.md)). Use it on routers the person has set aside for testing until 1.0.0.

## 0. Before anything

**Do not do these, ever:**

- Do not put the bot token, a join code, a bind code or the recovery code on any command line,
  yours or the router's. A command you send as `ssh root@router "..."` becomes the argv of the
  router's `sh -c`, which any account on the router can read in `/proc`, and it stays in your tool
  log. These go in on standard input only (steps 6 and 8). Never write them to UCI, a log or a
  file in the repository. The only one you may show, and only to the person, is the bind code of
  step 9, which they have to send to their bot.
- Do not run `rollcall init` yourself, and never print, log, store or repeat the **recovery code**.
  `init` prints it once; the person runs it in their own SSH session and writes the code on paper
  (step 5). It overrides both admin routers, so a copy in your tool log is a copy too many.
- Do not reboot, restart the network, run `wifi`, run `sysupgrade` or power-cycle a router unless
  the person said you may, for that action. Do not change `/etc/config/network`, `firewall` or
  `system` for rollcall: the package writes its own firewall rule.
- Do not use `--allow-untrusted`, `--force` or `--force-broken-world` with apk. The feed is signed:
  if apk refuses a package, something is wrong. Stop and report; never work around it.
- Do not run a command on a router the person did not name. Name the router literally in every
  command that changes something (see [Traps](#traps-found-in-the-lab)).
- Do not add a zone that faces the internet to `peer_zone`, or static peers, unless the person
  asked for exactly that.

Ask the person first: which routers, the name each one gets (1 to 32 characters from `a-z`, `0-9`
and `-`), which one is the first (primary admin), which one is the backup admin, and which ones
send to Telegram. A sender needs its own way to the internet. They also need a bot from
@BotFather; you will need its token in step 8.

## 1. Preconditions

Run on each router. Each line must print what is shown after `# expect`.

```sh
cat /etc/apk/arch                                   # expect: aarch64_cortex-a53
. /etc/openwrt_release; echo "$DISTRIB_ID $DISTRIB_RELEASE"   # expect: OpenWrt 25.12.<n>
command -v apk                                      # expect: /usr/bin/apk
grep '^Seccomp:' /proc/self/status                  # expect: Seccomp:	0 (the line exists: the kernel has seccomp)
apk list --installed | grep -cE '^(procd-ujail|procd-seccomp|ca-bundle)-'   # expect: 3 (fewer: see below)
```

- `aarch64_cortex-a53` is the only target that has run on a router. Another target builds
  (`aarch64_generic`, `arm_cortex-a7`, `arm_cortex-a9`, `mipsel_24kc`, `mips_24kc`, `x86_64`) but
  is untested on hardware: tell the person, and go on only with their yes.
- Not 25.12, or no `apk`: stop. These steps are for vanilla OpenWrt 25.12. An `.ipk` for 24.10
  is built but has never been installed on a router.
- No `Seccomp:` line: stop. The daemon refuses to run without its filter.
- Fewer than 3 sandbox packages: apk fetches them from the OpenWrt feeds in step 3, so
  `apk update` must succeed first.

## 2. Trust the feed

On each router. The key goes in first, then the feed for the router's own architecture.

```sh
wget -O /etc/apk/keys/rollcall.pem https://taipanbox.github.io/rollcall/rollcall.pem
sha256sum /etc/apk/keys/rollcall.pem
echo "https://taipanbox.github.io/rollcall/25.12/$(cat /etc/apk/arch)/packages.adb" >> /etc/apk/repositories.d/customfeeds.list
apk update
```

**Check:**

```sh
sha256sum /etc/apk/keys/rollcall.pem | cut -d' ' -f1
# expect: 1dd696c7afce0464688a5106229723f60c8cfb9bd2f6ec296ee5fec24f57ff39
grep -c taipanbox.github.io/rollcall /etc/apk/repositories.d/customfeeds.list   # expect: 1
apk search rollcall                                 # expect: rollcall-1.0.0_rc1-r1 (and luci-app-rollcall)
```

A different sum: delete `/etc/apk/keys/rollcall.pem`, remove the line from `customfeeds.list`,
and stop. If `apk search` finds nothing while the sum is right, apk did not trust the feed (it
drops an untrusted feed without a word): report the output of `apk update`.

## 3. Install

`luci-app-rollcall` is optional and pulls in `luci-base`: ask the person before you add it to a
router without LuCI.

```sh
apk add rollcall
```

**Check**, on the router:

```sh
apk list --installed | grep -E '^(rollcall|luci-app-rollcall)-'   # expect: rollcall-1.0.0_rc1-r1
id rollcall                                         # expect: uid=1660(rollcall) gid=1660(rollcall) ...
ls -ld /etc/rollcall | awk '{print $1, $3}'         # expect: drwx------ rollcall
uci -q get firewall.rollcall_1                      # expect: rule
for f in /usr/bin/rollcall /usr/bin/rollcalld /etc/init.d/rollcall /etc/hotplug.d/*/50-rollcall \
         /etc/seccomp/rollcall.json /etc/capabilities/rollcall*.json /lib/upgrade/keep.d/rollcall \
         /etc/config/rollcall /usr/share/rpcd/acl.d/luci-app-rollcall.json; do
  [ -e "$f" ] && ls -ln "$f"
done | awk '$3 != 0 || $4 != 0 {n++} END {print n+0}'   # expect: 0 (every file owned by root)
```

The last check is not a formality: the first lab build installed every file as `nobody`, which would
have let any process running as `nobody` replace a program root runs. Anything but 0: stop, and
`apk del` the packages.

The service is enabled and not started.

## 4. Mark the routers that send

On each router the person named as a sender (no secret is involved):

```sh
uci set rollcall.main.sender='1' && uci commit rollcall
```

**Check:** `uci get rollcall.main.sender` prints `1`.

## 5. Create the group (the person does this, not you)

Tell the person to open their own SSH session to the first router (`ssh -t root@<first router>`)
and type:

```sh
rollcall init --name <name>
```

It prints `Group home created with <name> as its primary admin.`, then the recovery code, once.
They write it on paper and keep it offline: it is the only way back if both admin routers are
lost. Messages start with the site name, `home` unless `option site` is set in
`/etc/config/rollcall`. When they say it is done:

```sh
ssh root@<first router> '/etc/init.d/rollcall start; sleep 5; rollcall status --json' \
  | python3 -c 'import json,sys; s=json.load(sys.stdin); print(s.get("initialised"), (s.get("self") or {}).get("admin"))'
```

**Check:** it prints `True primary`. `False None`: init did not run. `None None`: the daemon is
not running, see [Failures](#failures).

## 6. Add the other routers

For each other router, start its service, then pipe a fresh join code from the first router
straight into `rollcall join` on the new one. The code passes through the pipe only: never echo
it, and never keep it in a variable you print. It works once, for 10 minutes.

```sh
ssh root@<new router> '/etc/init.d/rollcall start'
ssh root@<first router> 'rollcall invite --json' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["join_code"])' \
  | ssh root@<new router> 'rollcall join --name <new name>'
```

The code names the first IPv4 address of the first router's peer-zone interfaces. If the new
router cannot reach that address, use `rollcall invite --json --address <an address it can reach>`.
`join` refuses a code given as an argument, by design.

**Check**, after 10 s:

```sh
ssh root@<first router> 'rollcall status --json' \
  | python3 -c 'import json,sys; print([(m["name"], m["state"]) for m in json.load(sys.stdin)["members"]])'
# expect: every router, each with "up"
```

`unheard` for a while after a join is normal; it should turn `up` within 30 s.

## 7. Roles

On the first router (the name always comes last, after `--`):

```sh
ssh root@<first router> 'rollcall roles backup -- <backup name>'
ssh root@<first router> 'rollcall roles sender -- <sender name>'     # once for each sender
```

**Check:** in `rollcall status --json`, the backup shows `"backup"` in its `roles` and each sender
`"sender"`. At most two routers are admins: the primary and one backup.

## 8. The bot token, on each sender

Ask the person for the token from @BotFather, in a file on your machine (`token.txt`, one line).
It goes to the router on standard input; `set-token` reads it from its environment, never from an
argument.

```sh
ssh root@<sender> 'IFS= read -r TELEGRAM_ROLLCALL_TOKEN && export TELEGRAM_ROLLCALL_TOKEN && rollcall set-token' < token.txt
```

**Expect:** `Bot token saved. Run rollcall bind-telegram next to bind the chat.` The reply never
repeats the token. Then make sure no token reached the log, without printing anything:

```sh
ssh root@<sender> 'logread | grep -c -E "[0-9]{6,}:[A-Za-z0-9_-]{20,}"'    # expect: 0
```

Anything but 0: tell the person to revoke the token in @BotFather, and repeat this step with the
new one. Ask the person whether to delete `token.txt` now.

`set-token` refuses on a router without the sender role (step 7). The lab ran this step on one
sender; run it on every router that sends.

## 9. Bind the chat

```sh
ssh root@<sender> 'rollcall bind-telegram'
```

It checks the token with Telegram first, then prints a code (10 digits) on its own line. Better,
the person runs the command in their own SSH session and sees the code there; otherwise give it to
them in your reply and nowhere else. They send exactly that code to their bot in a private chat within 10 minutes. Messages
from any other chat are ignored. Tell them that the announcements held so far (joins, role changes)
arrive together once the chat is bound.

**Check**, after they say they sent it:

```sh
ssh root@<sender> 'rollcall status --json' | python3 -c 'import json,sys; print(json.load(sys.stdin)["telegram"]["state"])'   # expect: ok
```

`not_bound`: the code has not arrived yet. `bot_blocked`: the bot is blocked in that chat.
`tls_failed`: the certificate check failed, nothing was sent; report it.

## 10. Check the sandbox, on every router

Run these on the router, in one SSH session, so that `$P` is the router's:

```sh
P=$(pidof rollcalld)
grep -E '^(Uid|Gid|NoNewPrivs|Seccomp|Seccomp_filters|CapEff):' /proc/$P/status
for t in /proc/$P/task/*; do grep -h '^Seccomp:' $t/status; done | sort | uniq -c
logread -e rollcalld | grep 'seccomp filter installed' | tail -n 1
logread -e rollcall | grep 'SO_BINDTODEVICE' | tail -n 1
ls /proc/$P/root/
```

**Expect:**

- `Uid` and `Gid` 1660 in every column, `NoNewPrivs: 1`, `Seccomp: 2`, `Seccomp_filters: 1`,
  `CapEff: 0000000000000000`.
- One count line, `<threads> Seccomp: 2`: every thread is filtered, none shows another value.
- `seccomp filter installed on every thread: 74 system calls of linux/arm64 allowed, any other ends
  the process`.
- `listening on port 7432 on <devices>; SO_BINDTODEVICE applied: true`.
- The jail, not the router's root: `dev etc proc sys tmp usr var`.

Measured on three routers on 2026-10-23 ([measured.md](measured.md)). `pidof` matches the process
name, so it never finds the `sh -c` your SSH command runs in.

## 11. Status

```sh
ssh root@<router> 'rollcall status'
ssh root@<router> 'rollcall status --json' | python3 -c 'import json,sys; s=json.load(sys.stdin); print(s["sandbox"]["state"], s["sender"])'
```

**Expect:** `enforced` and the name of the router that sends now. Anything but `enforced`: report
the `sandbox` object. The sender is `None` while no router can reach Telegram.

## Upgrading

`apk update && apk upgrade rollcall luci-app-rollcall` on each router (only the packages the
router has), then `/etc/init.d/rollcall restart` so the new daemon runs. apk keeps
`/etc/rollcall` and `/etc/config/rollcall`: the group, the roles and the token stay. Then run the
checks of steps 3 and 10 again.

## Removing

If the other routers stay in the group, first remove this router from it, on an admin router, so
the group key rotates without it:

```sh
rollcall remove -- <name>
```

Then on the router itself (leave `luci-app-rollcall` out if it was not installed):

```sh
apk del luci-app-rollcall rollcall
```

**Check:** `apk list --installed | grep -c rollcall` prints `0`, and
`uci show firewall | grep -c rollcall` prints `0` (the package removes its rule).

This keeps the router's keys, the configuration and the `rollcall` account. Remove them only when
the person wants everything gone; `/etc/rollcall` holds the router's keys and, on a sender, the bot
token:

```sh
rm -rf /etc/rollcall /var/run/rollcall /var/run/rollcalld
rm -f /etc/config/rollcall*
sed -i '/^rollcall:/d' /etc/passwd /etc/shadow /etc/group
```

**Check:**

```sh
grep -c '^rollcall:' /etc/passwd /etc/group      # expect: /etc/passwd:0 and /etc/group:0
cat /proc/net/udp /proc/net/udp6 /proc/net/tcp /proc/net/tcp6 2>/dev/null | grep -ci ':1D08 '   # expect: 0 (nothing on port 7432)
```

If the router was a sender and leaves for good, tell the person to revoke the token in @BotFather.

## Traps found in the lab

- **A timer started with `nohup ... &` over SSH dies with the session.** In the lab a rollback
  that was meant to put a route back after three minutes vanished when the SSH command returned,
  and the route stayed removed for about 20 s with no timer behind it. A timed rollback, after a
  change the person approved, is started detached and then checked from a new session:

  ```sh
  start-stop-daemon -S -b -x /bin/sh -- /root/restore.sh
  pgrep -f '[r]estore.sh'                         # from a new SSH session: expect a process id
  ```

- **A helper that reuses a shell variable can send a command to the wrong router.** In the lab a
  helper function set the same variable as the loop that called it, and one `join` went to the
  first router instead of the new one (it refused, as it should). Name the router literally in
  every command that changes something, or check the target first with
  `ssh root@<router> cat /proc/sys/kernel/hostname`.

## Failures

| What you see | Cause | Do |
|---|---|---|
| `rollcalld: refusing to run without its seccomp filter: ...` | the kernel refused the filter | report the line; never try to run the daemon without it |
| `refusing to start without a current snapshot ...` | root's snapshot of the firewall, network and system facts is missing or older than those files | run `rollcall snapshot` as root and read its error, then `/etc/init.d/rollcall restart` |
| `refusing to listen: ...` | the kernel does not show `no_new_privs` or the filter for the daemon | report it |
| `rollcalld is not running` | the service is stopped, or it stopped at one of the lines above | `logread -e rollcall \| tail -n 30` |
| `rollcall join reads the join code from standard input ...` | the code was given as an argument | step 6, through the pipe |
| `no join code on standard input` | `rollcall invite` failed, so the pipe carried nothing | run `rollcall invite --json` and read its `error` |
| `TELEGRAM_ROLLCALL_TOKEN is not set` / `... does not hold a bot token` | the file was empty or holds more than the token | step 8 with a file of one line |
| `set-token` says the router does not have the sender role | step 7 skipped for this router | step 7 |
| `... This router sends only with option sender '1' ...` | step 4 skipped | step 4, then `/etc/init.d/rollcall restart` |
| a member stays `unheard` or `silent` | it cannot reach the others on port 7432 in a peer zone | check that both routers are in the zone named by `peer_zone`, and `uci -q get firewall.rollcall_1` |

## Reporting

Open an issue at [TAIPANBOX/rollcall](https://github.com/TAIPANBOX/rollcall/issues) with the
router, `cat /etc/apk/arch`, `cat /etc/openwrt_release`, the package version and the log, with
tokens and codes taken out. A security problem goes to [SECURITY.md](../SECURITY.md), never an
issue.
