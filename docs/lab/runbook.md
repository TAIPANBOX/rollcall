# Lab runbook: Task 27 on flint2, beryl1 and beryl2

This runbook proves the v1 group on three lab routers: flint2 (primary and sender), beryl1 (backup admin) and beryl2. It reaches the routers with `lab_ssh` (Tailscale SSH by default, see step 0) and uses, for the hostile-LAN checks, the Mac on flint2's LAN. No other router is used.

**Status: draft, not yet run.** The commands below were checked against `rollcall help` of Task 21 (fix round 1). The status report is described in `luci-app-rollcall/STATUS-JSON.md`. If a command differs from the CLI's usage text on the first run, correct it here in the same change, and do not improvise on a router.

## Rules for the run

- Each step that reboots, powers off, unplugs, upgrades or changes the Wi-Fi of a router waits for the operator's go for that step.
- The Telegram bot token never goes into a file or onto a command line. It travels from the environment on the Mac to `rollcall set-token` on standard input (step 3.6).
- Expected results come from the message templates in `internal/deliver/templates.go` and from the design. A result that differs is recorded as it is, not forced to match.
- Chat timestamps are approximate by design. Record the local time of each physical action and the time of each chat line.
- Keep `$RUN` outside the repository. It holds captures of group traffic.

## 0. Setup on the Mac

Every router command goes through `lab_ssh <router> '<command>'`. It is Tailscale SSH by default. When Tailscale is not running on the Mac, write an ssh config file for the run, `$RUN/ssh_config`, with a `Host` entry per router name (its LAN address and the lab key), and set `LAB_SSH="ssh -F $RUN/ssh_config"`; the Mac's own `~/.ssh/config` is not touched. No router address is written in this repository.

```sh
cd ~/Development/rollcall
RUN="$HOME/rollcall-lab/$(date +%Y%m%d-%H%M)"
mkdir -p "$RUN"
lab_ssh() { h=$1; shift; sh -c "${LAB_SSH:-tailscale ssh}"' "$0" "$@"' "root@$h" "$@"; }
for h in flint2 beryl1 beryl2; do
  echo "== $h"
  lab_ssh $h 'grep -E "DISTRIB_(RELEASE|ARCH)" /etc/openwrt_release'
done
```

Expected: on each of the three routers, `DISTRIB_RELEASE='25.12.x'` and `DISTRIB_ARCH='aarch64_cortex-a53'`. Any other architecture stops the run, because the packages below are for `aarch64_cortex-a53` only.

Define the two status helpers once. They are used in later steps:

```sh
lab_status() { lab_ssh flint2 'rollcall status --json' | python3 -m json.tool; }
lab_members() {
  lab_ssh flint2 'rollcall status --json' | python3 -c 'import json,sys; s=json.load(sys.stdin); print(s.get("initialised"), [(m["name"], m["state"], m["roles"]) for m in s.get("members", [])])'
}
```

Expected: both definitions return without error.

## 1. Build the packages (Mac only, no router touched)

The packages are built on GitHub by the `lab-packages` job of the ci workflow, which runs only when the workflow is started by hand, so the Mac needs neither Docker nor apk-tools v3. Start it on the branch under test and fetch its artifact:

```sh
cd ~/Development/rollcall
gh workflow run ci.yml --ref "$(git rev-parse --abbrev-ref HEAD)"
sleep 15
LAB_RUN=$(gh run list --workflow ci.yml --event workflow_dispatch --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch "$LAB_RUN" --exit-status --interval 30
rm -rf dist/pkg && gh run download "$LAB_RUN" -n lab-packages -D dist/pkg
ls dist/pkg/aarch64_cortex-a53/*.apk dist/pkg/luci/*.apk
shasum -a 256 dist/pkg/aarch64_cortex-a53/*.apk dist/pkg/luci/*.apk
```

Expected: the run ends green (the mutation job of the same run only reports). The listing shows the `rollcall` package in `dist/pkg/aarch64_cortex-a53/` and `luci-app-rollcall` in `dist/pkg/luci/`, and the checksums equal the ones the run's build step printed. Record the run ID and the commit in `$RUN`.

## 2. Install on each router

Copy the packages to each router over standard input, with no scp:

```sh
for h in flint2 beryl1 beryl2; do
  for f in dist/pkg/aarch64_cortex-a53/*.apk dist/pkg/luci/*.apk; do
    cat "$f" | lab_ssh $h "mkdir -p /tmp/rollcall-lab && cat > /tmp/rollcall-lab/$(basename "$f")"
  done
done
```

Expected: no output. Each router has the package files in `/tmp/rollcall-lab`, a directory of their own, so the install below takes nothing else that lies in `/tmp`.

Install them:

```sh
for h in flint2 beryl1 beryl2; do
  echo "== $h"
  lab_ssh $h 'apk add --allow-untrusted /tmp/rollcall-lab/*.apk && apk info -v rollcall'
done
```

Expected: apk installs the packages and resolves the dependencies (`procd-seccomp`, `procd-ujail`, `ca-bundle`) from the router's feeds. The last line names `rollcall` at version `0.0.0_rcN`, N the number of the ci run that built it, so a later lab build upgrades an earlier one. A dependency that cannot be resolved stops the install; record the message.

## 3. Init, join, roles, token and bind

The members are named `flint2`, `beryl1` and `beryl2`. `init` and `join` take the name with `--name`; without it they use the router's hostname, and refuse one that is not a valid name (a-z, 0-9 and `-`, at most 32 characters).

The daemon reads `/etc/config/rollcall` when it starts, and it sends to Telegram only on a router with `option sender '1'` there. The postinst enables the service but does not start it. `init` works on the state directory by itself; `join` runs inside the daemon, so the daemon is started before `join`.

### 3.1 Init on flint2 (primary)

```sh
lab_ssh flint2 "uci set rollcall.main.sender='1' && uci commit rollcall"
lab_ssh flint2 'rollcall init --name flint2 && /etc/init.d/rollcall enable && /etc/init.d/rollcall start && sleep 5'
lab_members
```

Expected: the group is created and the recovery code is printed once. Write the recovery code on paper and keep it offline. Do not paste it into a file, a chat or a command in this runbook. `lab_members` prints `True [('flint2', 'up', ['primary'])]`.

### 3.2 Invite and join beryl1

```sh
lab_ssh flint2 'rollcall invite'
```

Expected: a line saying the join window is open for 10 minutes, then the join code on its own line, valid for one use. Copy it by hand into the next command, which hands it to `rollcall join` on standard input: join never takes the code on its command line, where every process on the router could read it. The code names the first IPv4 address of flint2's peer-zone interfaces; if beryl1 cannot reach that address, run `rollcall invite --address <an address of flint2 that beryl1 reaches>` instead.

```sh
echo '<join code>' | lab_ssh beryl1 '/etc/init.d/rollcall enable && /etc/init.d/rollcall start && sleep 5 && rollcall join --name beryl1'
lab_members
```

Expected: `lab_members` lists `beryl1` as `up`. Its roles are empty.

### 3.3 Make beryl1 backup admin

```sh
lab_ssh flint2 'rollcall roles backup -- beryl1'
lab_members
lab_ssh beryl1 'rollcall status --json' | python3 -c 'import json,sys; print(json.load(sys.stdin)["self"]["admin"])'
```

Expected: `beryl1` shows `backup` in `lab_members`. The last command prints `backup`.

### 3.4 Invite and join beryl2

```sh
lab_ssh flint2 'rollcall invite'
echo '<join code>' | lab_ssh beryl2 '/etc/init.d/rollcall enable && /etc/init.d/rollcall start && sleep 5 && rollcall join --name beryl2'
lab_members
```

Expected: three members, all `up`.

### 3.5 Make flint2 a sender

```sh
lab_ssh flint2 'rollcall roles sender -- flint2'
lab_members
```

Expected: `flint2` shows `primary` and `sender`. Only senders hold the bot token: `set-token` refuses on a router without the sender role. flint2 got `option sender '1'` in step 3.1, before its daemon started.

### 3.6 Set the bot token on flint2

The token is in the environment on the Mac, loaded from the local secrets file that is kept outside the repository. It reaches the router on standard input, and `rollcall set-token` reads it from the environment:

```sh
printf '%s\n' "$TELEGRAM_ROLLCALL_TOKEN" | lab_ssh flint2 'IFS= read -r TELEGRAM_ROLLCALL_TOKEN && export TELEGRAM_ROLLCALL_TOKEN && rollcall set-token'
```

Expected: `Bot token saved. Run rollcall bind-telegram next to bind the chat.` The reply never repeats the token. If the variable is empty on the Mac, `set-token` reports that `TELEGRAM_ROLLCALL_TOKEN is not set`. It never takes the token as an argument.

Check that no token-shaped string reached the router log, without printing anything secret:

```sh
lab_ssh flint2 'logread | grep -c -E "[0-9]{6,}:[A-Za-z0-9_-]{20,}"'
```

Expected: `0`. Any other number means a token was logged. Revoke the token in BotFather, then repeat step 3.6 with the new one.

### 3.7 Bind the Telegram chat

```sh
lab_ssh flint2 'rollcall bind-telegram'
```

Expected: a line asking to send the code to the bot within 10 minutes, then the bind code on its own line (10 digits). `bind-telegram` checks the token with Telegram first, so a wrong token fails at once. The operator sends the code to the bot in a private chat from the phone. Then:

```sh
lab_ssh flint2 'rollcall status --json' | python3 -c 'import json,sys; print(json.load(sys.stdin)["telegram"])'
```

Expected: `{'state': 'ok', 'last_ok': '<time>'}`. `not_bound` means the chat has not answered the bind code yet. `bot_blocked` means the bot is blocked in that chat. The chat stays quiet after binding, because nothing has happened yet; a bind confirmation, if the CLI sends one, is recorded as it is.

## 4. Sandbox proof on each router

```sh
for h in flint2 beryl1 beryl2; do
  echo "== $h"
  lab_ssh $h 'grep -E "NoNewPrivs|Seccomp|Cap" /proc/$(pidof rollcalld)/status'
  lab_ssh $h 'for t in /proc/$(pidof rollcalld)/task/*; do grep -h "^Seccomp:" $t/status; done | sort | uniq -c'
  lab_ssh $h 'logread -e rollcalld | grep "seccomp filter installed" | tail -n 1'
  lab_ssh $h 'grep -E "^(Uid|Gid)" /proc/$(pidof rollcalld)/status; grep "^rollcall:" /etc/passwd'
  lab_ssh $h 'ls -l /proc/$(pidof rollcalld)/root/'
done
```

Expected, per router:

- `NoNewPrivs: 1`, `Seccomp: 2` and `Seccomp_filters: 1`: the filter is the daemon's own (procd installs none, it cannot filter a static program).
- Every thread shows `Seccomp: 2` (one count line, `Seccomp:` with 2), none another value.
- The log line `rollcalld: seccomp filter installed on every thread: N system calls of linux/arm64 allowed, any other ends the process`, N the number of names in `sh packaging/seccomp/generate.sh aarch64_cortex-a53` (74 when this line was written).
- All five `Cap` lines (`CapInh`, `CapPrm`, `CapEff`, `CapBnd`, `CapAmb`) read `0000000000000000`, because `option icmp '0'` is the default. A non-zero line is a finding: record it, do not count it as a pass.
- `Uid` and `Gid` read `1660`, and `/etc/passwd` has a `rollcall` line with uid 1660.
- The listing of `/proc/<pid>/root/` is the jail: a few directories the init script mounts. It is not the router's root. Compare it with `ls -l /`, which the operator can run on the same router.

The device binding of the listener is the last sandbox question:

```sh
lab_ssh flint2 'logread -e rollcall | grep -i -E "device|bind"'
```

Expected: one line at each start, `rollcalld <version>: listening on port 7432 on <devices>; SO_BINDTODEVICE applied: true` (or `false`, when the kernel refused the pin to the unprivileged daemon). Copy the line as it is into the results log (step 10). If no such line exists, record that the daemon does not log the binding. Do not record it as working.

## 5. Topology A: routers as wired (separate LANs on one upstream switch)

Start with `lab_members` showing three members `up`. Keep the results log at `"$RUN/chat-log.txt"`: the time of each action, each chat line, and the delay.

### 5.1 Power pull on beryl2

The operator pulls beryl2's power at time T.

Expected: within about 30 seconds, a chat line `Home: beryl2 stopped answering at HH:MM.` Then `lab_members` shows `beryl2` as `silent`.

The operator plugs beryl2 back in.

Expected: a chat line `Home: beryl2 rebooted unexpectedly at HH:MM, back after N min.` (or the form without the downtime), and `beryl2` is `up` again.

### 5.2 Clean reboot of flint2

flint2 is the only sender in this plan, so its messages can leave only after it is back.

```sh
lab_ssh flint2 'reboot'
```

Expected: after flint2 returns, one chat line `Home: flint2 rebooted as planned at HH:MM, back after N min.` It arrives after the reboot, because flint2 is the only router that can reach Telegram. Record the delay.

### 5.3 Sysupgrade of beryl1, same release (answers hardware question Q1)

The sysupgrade image is the one for beryl1's board and the release it already runs. Using the same release keeps the classification to planned or unplanned. Copy the image into `$RUN` and check its checksum against the release's `sha256sums` file:

```sh
lab_ssh beryl1 'ubus call system board'
cat "$RUN/sysupgrade.bin" | lab_ssh beryl1 'cat > /tmp/sysupgrade.bin'
lab_ssh beryl1 'sha256sum /tmp/sysupgrade.bin'
```

Expected: the printed hash matches the `sha256sums` entry for that image. The `ubus` call runs in the operator's root shell, not in the daemon, which has no ubus access.

```sh
lab_ssh beryl1 'sysupgrade -v /tmp/sysupgrade.bin'
```

Expected: the upgrade keeps the configuration (no `-n`). The SSH session ends at the reboot. About two minutes later the chat shows either:

- `Home: beryl1 rebooted as planned at HH:MM, back after N min.` The going-down message was sent, so `shutdown()` ran during sysupgrade. Q1 is **yes**.
- `Home: beryl1 rebooted unexpectedly at HH:MM, back after N min.` The going-down message was not sent. Q1 is **no**.

Record the line that appears. Step 9 runs in this same reboot, so no second reboot is needed.

### 5.4 Unplug the WAN of flint2

The operator unplugs flint2's WAN cable at time T.

Expected: no chat line while flint2 is the only sender and has no internet, because nothing can reach Telegram. When the cable goes back in, one line arrives: either `Home: WAN was down from HH:MM to HH:MM (N min)` or `Home: internet was down from HH:MM to HH:MM (N min)`. Both wordings exist in the templates, so record which one arrives.

## 6. Topology B: 802.11s mesh between beryl1 and beryl2

Changing the Wi-Fi is a step that needs the operator's go. The radio name and the mesh settings depend on the board. Set up an 802.11s mesh point on `radio0` of both routers as the OpenWrt 25.12 802.11s page describes: mode `mesh`, one `mesh_id`, SAE with a lab key kept outside the repository, and bridged to `lan`. Record the UCI you used in the results log.

Check the mesh link before the test. Read the name of the mesh interface from the first command, then count its peers with the second:

```sh
for h in beryl1 beryl2; do
  echo "== $h"
  lab_ssh $h 'iw dev'
done
lab_ssh beryl2 'iw dev <mesh interface> station dump | grep -c ^Station'
lab_members
```

Expected: each router lists an interface of type `mesh point`. The peer count on beryl2 is `1`, the other Beryl AX. `lab_members` shows three members `up`.

### 6.1 Drop the mesh link on beryl2 for three minutes

The restore runs on the router, so the test ends even if the SSH session drops:

```sh
lab_ssh beryl2 'nohup sh -c "wifi down; sleep 180; wifi up" >/dev/null 2>&1 &'
```

Expected: within about 30 seconds, the chat shows `Home: beryl2 lost contact HH:MM to HH:MM but stayed up: a link problem, not a reboot.` No `rebooted` line appears. After three minutes the radios are back. `lab_members` shows `beryl2` as `up`, and the mesh peer is listed again.

## 7. Topology C: beryl2 behind beryl1's NAT, with static peers

**Open decision, not yet taken.** beryl2's static peer has to be an address that flint2 can reach across beryl1's NAT, which means flint2's WAN side. The packaged firewall opens UDP and TCP 7432 only for the zones in `peer_zone` (`lan` by default). The config allows a `wan` peer zone only together with static peers. Opening the port on the WAN side changes what the daemon exposes, so the controller decides how flint2 accepts 7432 from beryl2's side before this topology runs.

Once that is decided, the steps are:

```sh
lab_ssh flint2 'ip -4 -br addr'
```

Expected: the WAN address of flint2 on the upstream switch. Call it `FLINT2_WAN`, then:

```sh
lab_ssh beryl2 "uci add_list rollcall.main.peer='$FLINT2_WAN:7432' && uci commit rollcall && /etc/init.d/rollcall restart"
lab_members
```

Expected: `beryl2` is `up` in `lab_members` before any power test. If it is not, stop and record the state. The group did not form through the NAT, which is a finding and not a pass.

Then repeat step 5.1 with beryl2 behind the NAT. The expected chat lines are the same: `stopped answering` within about 30 seconds, then `rebooted unexpectedly`.

## 8. Hostile LAN checks, from the Mac on flint2's LAN

### 8.0 Set the target and the interface

```sh
cd ~/Development/rollcall
RUN="$HOME/rollcall-lab/$(date +%Y%m%d-%H%M)"; mkdir -p "$RUN"
FLINT2_LAN=<flint2 LAN IPv4 address>   # from: lab_ssh flint2 'uci -q get network.lan.ipaddr'
TARGET="$FLINT2_LAN:7432"
IF=$(route -n get "$FLINT2_LAN" | awk '/interface:/ {print $2}')
echo "interface: $IF"
```

Expected: `IF` names the Mac interface that is cabled to flint2's LAN. macOS can send traffic for a subnet out of the wrong interface when two of its interfaces share that subnet. If `IF` is not the cabled interface, the packets never reach flint2. For IPv6, use flint2's link-local address with the Mac's zone, and bracket it: `TARGET='[fe80::...%enX]:7432'`.

Keep the sudo password valid for the background captures:

```sh
sudo -v
```

### 8.1 Capture steady state for two minutes

```sh
sudo tcpdump -i "$IF" -s 0 -w "$RUN/lan.pcap" 'udp port 7432' &
sleep 120
sudo pkill -INT tcpdump
tcpdump -nr "$RUN/lan.pcap" 2>/dev/null | wc -l
```

Expected: a count above zero. Each router sends a heartbeat about every 5 seconds, so about 24 packets per router in two minutes, plus occasional roster packets.

### 8.2 Replay one captured packet

```sh
go run ./tools/replay -pcap "$RUN/lan.pcap" -to "$TARGET" -count 1
lab_members
```

Expected: the tool prints `replayed 1 payloads to <flint2 LAN>:7432`. No chat line appears, and every member stays `up`. The replay window drops the packet without an event.

### 8.3 Replay ten captured packets

```sh
go run ./tools/replay -pcap "$RUN/lan.pcap" -to "$TARGET" -count 10
lab_members
```

Expected: the same as step 8.2, with `replayed 10 payloads`. No chat line, all members `up`.

### 8.4 Flood with 10 000 random datagrams

```sh
sudo tcpdump -i "$IF" -s 96 -w "$RUN/flood.pcap" "udp and dst port 7432 and dst host $FLINT2_LAN" 2>/dev/null &
sleep 2
go run ./tools/flood -to "$TARGET" -n 10000 -size 1200
sleep 2
sudo pkill -INT tcpdump
tcpdump -nr "$RUN/flood.pcap" 2>/dev/null | wc -l
```

Expected: the tool prints `sent 10000 random datagrams of 1200 bytes to <flint2 LAN>:7432`. The capture counts about 10 000 packets on the wire. A smaller count means loss between the Mac and flint2; record the number.

Then check the router and the chat:

```sh
lab_members
lab_ssh flint2 'rollcall status --json' | python3 -c 'import json,sys; [print(i["time"], i["text"]) for i in json.load(sys.stdin)["incidents"][:3]]'
```

Expected:

- Every member stays `up`. None goes `silent`, so no member is muted by the flood.
- `telegram` on flint2 still reads `ok`.
- The incident list may hold one flood line, `a flood of packets that failed authentication reached the group at HH:MM`. That line is the designed `under_flood` message (`internal/deliver/templates.go`). Record whether it reached the chat. The plan's wording says "no chat message", which is an open point for the controller, so do not decide it here.
- No `stopped answering` or `rebooted` line appears because of the flood.

## 9. Hardware questions

Both questions are answered in the same sysupgrade as step 5.3. The answer for Q1 is already recorded there.

### Q2: does a script under /lib/upgrade/ run during sysupgrade?

Put a probe in place before the sysupgrade of step 5.3. It writes into `/etc/rollcall/`, which the package keeps across upgrades through `/lib/upgrade/keep.d/rollcall`:

```sh
lab_ssh beryl1 'cat > /lib/upgrade/rollcall-hook-probe <<"EOF"
#!/bin/sh
echo "hook ran $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> /etc/rollcall/hook-probe
EOF
chmod +x /lib/upgrade/rollcall-hook-probe'
lab_ssh beryl1 'ls -l /lib/upgrade/rollcall-hook-probe; test -e /etc/rollcall/hook-probe && echo "already present" || echo "no probe output yet"'
```

Expected: the probe file is listed, and the second command prints `no probe output yet`.

After beryl1 is back from the sysupgrade:

```sh
lab_ssh beryl1 'cat /etc/rollcall/hook-probe'
```

Expected, and what each result means:

- A line `hook ran <UTC time>`: a hook under `/lib/upgrade/` ran, and it ran before the configuration backup. Q2 is **yes**.
- No file: **not observed**. The hook may have run after the backup, or it may not run at all. The test cannot separate those two, so do not record it as "no hook".

Clean up the probe after recording the result:

```sh
lab_ssh beryl1 'rm -f /lib/upgrade/rollcall-hook-probe /etc/rollcall/hook-probe'
```

Record both answers in `docs/notes/hardware-2026-10.md`, with the date and the line you saw. Do not paste chat contents or tokens into that file.

## 10. Results

- `"$RUN/chat-log.txt"` holds the time of each physical action, each chat line as it arrived, and the delay. Copy the chat lines exactly.
- `lab_members` and `lab_status` at each stage show the state. Record the output for the start and end of each topology.
- The Task 28 report takes the results in its "Ran it" section, with the timings and chat lines.
- If a router does not come back within 10 minutes after a reboot, stop, record the state, and do not start a second action on that router.
- If the chat shows a line you cannot explain, record it verbatim before anything else.
