# rollcall: OpenWrt router group design (approved 2026-10-22)

Status: approved on 2026-10-22, together with the answers to the open questions in
section 9. Security is specified in the companion document
`2026-10-22-rollcall-security.md`, which overrides this one where they differ.
Nothing is built yet.

Provenance: lines marked `@decided 2026-10-22` paraphrase decisions taken in the
session of that date; everything else is `@claude` (my design, to be checked).
Facts marked `@source` were read from the named primary source on 2026-10-22.

## 1. Intent

A router that dies cannot report its own death. Every OpenWrt notifier found in the
2026-10-22 research runs on one router and talks only about itself; fleet tools that
see several routers need a server somewhere. `rollcall` closes that gap without a
server: the routers of one site watch each other and report through whichever of
them can still reach the user.

- `@decided 2026-10-22`: build for other people first (community OpenWrt users);
  our own lab needs come after.
- `@decided 2026-10-22`: several routers in one site run the service, continuously
  exchange their state over the local network, and when something happens (internet
  lost, a reboot, an upgrade, other events) one router that is still connected to
  Telegram reports it to the bot.
- `@decided 2026-10-22`: the group may be a mesh, or separate routers on one network
  each serving its own DHCP and DNS. Both must work.
- `@decided 2026-10-22`: the routine "I am alive" traffic never shows up in the chat;
  the chat gets a message only when a router stops answering or an event happens.

Who it is for: a home or small office with one to about ten OpenWrt devices (a main
router plus access points, a mesh, or several routers), no always-on server, and a
phone with Telegram.

## 2. Goals, non-goals, anti-goals

Goals for v1:

1. Group membership over the LAN: automatic discovery on a shared segment, static
   peer addresses everywhere else.
2. Liveness: a member that stops answering is reported within 30 s by default.
3. Classification: planned reboot, unplanned reboot (crash or power loss look the
   same from outside), upgrade (with old and new version), link loss while the
   router stayed up.
4. Internet state per member: WAN up/down, reachability by probes, switch to a
   backup uplink.
5. One replicated event log: an event seen by any member survives the loss of that
   member.
6. Exactly one sender at a time, chosen among the members that currently reach
   Telegram; delivery at least once; duplicates rare and recognisable.
7. Delivery after recovery, with start, end and duration, when nobody could reach
   Telegram during the incident.
8. A single router works on its own (a group of one) as a plain notifier with an
   outage queue.
9. Pairing with a join code; the bot token reaches every member through pairing.
10. A LuCI page: members, their state, recent events, current sender, and a plain
    warning when the group has no second way out to the internet.
11. Packages for OpenWrt 24.10 (ipk) and 25.12 (apk) on aarch64, arm, mips, mipsel
    and x86_64.

Non-goals for v1: dashboards and long-term metrics (Prometheus exporters already
exist in the feeds); a conversational bot beyond `/status` and `/events`; actions
such as restarting interfaces; pushing configuration to several routers; running on
non-OpenWrt devices (they can become ping targets later).

Anti-goals (a failure even if it technically works):

- Chat noise: heartbeats in the chat, or one incident producing a message per router.
- Silent loss: an event that some member saw and nobody ever delivered or reported
  as expired.
- Needing a server, a cloud account, or any third-party service besides the
  notification channel itself.
- Wearing out router flash.
- Members fighting over the bot token (Telegram's 409 conflict on polling).
- Listening on the internet side of any router.

## 3. Constraints

- Go, one static binary (`CGO_ENABLED=0`, `-ldflags "-s -w"`). Size budget
  ~8 MiB installed, RSS budget ~15 MB on a 128 MB router: estimates, to be measured.
- Clock: most routers have no RTC. At boot OpenWrt's `sysfixtime` sets the clock to
  the newest file time under `/etc` if that is later than the current time
  (`@source` openwrt/openwrt `package/base-files/files/etc/init.d/sysfixtime`), so
  after a power cut the clock is wrong until NTP answers, and during an internet
  outage NTP does not answer.
- Telegram: avoid more than one message per second in one chat, at most 20 messages
  per minute in a group, about 30 per second overall (`@source`
  core.telegram.org/bots/faq). Long polling is unavailable while a webhook is set.
  Two pollers on one token conflict (known from operating our own bots).
- `sysupgrade` removes installed packages; files listed in `/etc/sysupgrade.conf`
  or `/lib/upgrade/keep.d/*` survive (`@source` base-files). Config and state must be
  listed there.
- Flash has limited write cycles: heartbeats live in RAM only.
- Both package managers: opkg/ipk on 24.10, apk v3 on 25.12.

## 4. Architecture

### 4.1 One process

A procd service `rollcalld` with these parts: membership, local event sources,
internet probes, event log, sender election, channels (Telegram first, ntfy second
behind the same interface), and a local control socket used by the CLI and LuCI.
Later modules (section 8) are more event sources inside the same binary.

### 4.2 Membership and transport

Every member sends a small authenticated UDP heartbeat every 5 s to each known peer.
It carries: member ID (stable, from pairing), host name, boot ID (random per boot),
uptime, OpenWrt and service versions, WAN state, internet reachability, Telegram
reachability with the time of the last successful API call, sender priority, its own
latest history entry and one digest over the latest entries it holds from all origins
(for catch-up and fork detection; details are compared over TCP when digests differ),
wall clock, monotonic clock, and whether the wall clock is trusted (NTP-synced since
this boot).

Discovery, in order of preference:

1. IPv6 link-local multicast announce on the configured interfaces (default `lan`),
   the way usteer (`ff02::4150`, port 16720) and alfred already do it on OpenWrt; it
   needs no IPv4 addressing. Works wherever members share one L2 segment: a main
   router with access points, an 802.11s or batman-adv mesh, routers whose WAN ports
   sit on one switch. Announcing through umdns (as DAWN does) is an option when umdns
   is installed; the builder decides.
2. Static peers (IP or host name) in `/etc/config/rollcall`, for cascaded NAT, routed
   segments and routed meshes (Babel, OLSR).
3. Overlay addresses (WireGuard, Tailscale) for several sites: just static peers.

Failure detection: suspect after 3 missed heartbeats, silent after 6 (30 s), both
configurable. Before declaring a member silent, ask another member to probe it
(indirect probe, as in SWIM), so one broken link in a mesh does not look like a dead
router. Membership is a small own implementation, not hashicorp/memberlist (decided
for security reasons, see the security document, section 4).

Heartbeats use UDP; larger messages (join, roster, keys, catch-up) use short TCP
connections on the same port (security document, 5.4).

Firewall: the package adds one rule for its port (UDP and TCP), limited to the zones
named in its config. Nothing is opened towards the internet.

### 4.3 Events

An event has: ID (origin member ID plus a per-origin sequence number), type, subject
member, witnesses, start and end (wall time, monotonic offset, clock-trust flag),
details, and delivery state (delivered at, by whom).

Types in v1: `member_silent`, `member_back`, `reboot_planned`, `reboot_unplanned`,
`upgraded`, `link_lost` (member stayed up), `wan_down`, `wan_up`, `internet_lost`,
`internet_restored`, `uplink_switched`, `member_joined`, `member_left`.

Classification when a silent member comes back:

| Before silence | On return | Event |
|---|---|---|
| announced "going down" | new boot ID, same version | `reboot_planned` |
| nothing announced | new boot ID, same version | `reboot_unplanned` |
| anything | new boot ID, new OpenWrt version | `upgraded` (old -> new) |
| nothing announced | same boot ID | `link_lost`: it stayed up, the path to it broke |

Coalescing: events that share a cause inside a short window become one incident and
one message. Example: the main router reboots, every access point loses internet,
the chat gets one message about the main router with the outage duration, not five.
A site-wide internet loss is one incident naming all witnesses.

History is a signed hash chain per member, with witness statements, fork detection,
corrections when a router comes back, and (v1.1) checkpoints signed by a majority; see
the security document, sections 5.7 to 5.9.

Replication: a member whose heartbeat digest differs from a peer's compares heads with
it over TCP and fetches the missing range. The log is bounded (default 500 events or 30
days). It lives in RAM and is flushed to flash at most once a minute when something
new happened, and on clean shutdown. Copies on the other members cover a member that
loses RAM in a power cut.

### 4.4 Time

A witness with a trusted clock stamps the event. A member with an untrusted clock
(fresh boot, no NTP) stamps with its monotonic clock plus the offset learned from a
trusted peer's heartbeat. If no member is trusted, the message says the times are
approximate. Messages use the router's configured time zone.

### 4.5 Who sends

Eligible: members with a channel configured, internet reachable, and a successful
Telegram API call within the last 60 s. Sender: the eligible member with the highest
configured priority, then the lowest member ID. Every member computes the same answer
from the shared view; there is no consensus protocol, the same idea as VRRP choosing
which router holds an address.

The sender delivers undelivered incidents oldest first, marks them delivered, and the
acknowledgement spreads with the heartbeats. If an incident stays unacknowledged for
a grace period and the sender has gone silent, the next eligible member sends it.
After a partition both halves may send the same incident; each message carries a
short incident ID so a duplicate is obvious. At least once is chosen on purpose: a
rare duplicate is better than silence.

v1 is push-only (`@decided 2026-10-22`): no commands, no polling, so no 409
conflicts. `getUpdates` is used once, during chat binding (security document,
section 9). If commands such as `/status` come later, only the current sender polls,
and the old sender stops before the new one starts. No webhooks, because they need an
inbound port from the internet.

### 4.6 Local event sources on OpenWrt

- Boot: compare boot ID, the stored OpenWrt version and the shutdown marker.
- Shutdown: the init script stops early (before `network`), writes a clean-shutdown
  marker and tells the peers "going down".
- Interfaces: netifd hotplug (`/etc/hotplug.d/iface`) or ubus `network.interface`
  events.
- Backup uplink: mwan3 hotplug when mwan3 is installed; otherwise a change of the
  default route's interface.
- Internet probes: DNS and TCP 443 to configurable targets every 10 s (they need no
  extra privileges); ICMP is optional and adds `CAP_NET_RAW` only when enabled;
  `internet_lost` after 3 failures in a row.
- Upgrade start: open. A script under `/lib/upgrade/` is a candidate hook (to verify
  on hardware); without it the upgrade is still classified on return (table above).

### 4.7 Pairing and secrets

Superseded in detail by the security document (sections 5 and 6): per-member
identities, a signed roster with an admin key, join codes with a one-time secret,
the token only on members with the `sender` role. The summary below stays for
orientation.

- `rollcall init` on the first router creates the group key and prints a join code
  (QR in LuCI). `rollcall join <code>` on the others. The code carries the group key
  and one bootstrap address.
- The bot token and chat ID travel to members over the authenticated channel and are
  stored root-only in `/etc/rollcall/`, kept across upgrades through `keep.d`.
- Every packet is authenticated with the group key and protected against replay
  (boot ID plus counter). The token never appears in heartbeats, logs or LuCI
  responses.
- `rollcall rotate` replaces the key for the members present; absent ones rejoin.

### 4.8 Topologies

| Topology | Discovery | Who reaches Telegram when the main line is down | What the user gets |
|---|---|---|---|
| One router | none | nobody | outage report after recovery |
| Main router plus access points, one L2 | multicast | nobody | everything after recovery, with full timeline; member deaths in real time while internet is up |
| 802.11s / batman-adv mesh | multicast over the mesh | nobody, unless a node has its own uplink | as above, plus `link_lost` for radio drops |
| Routed mesh (Babel, OLSR) | static peers | as above | as above |
| Separate routers, WANs on one upstream switch, each with own LAN and DHCP | multicast on the shared segment, or static | any member with its own second uplink | real time if a second uplink exists |
| Cascaded NAT | static peers | as above | as above |
| Several sites over WireGuard or Tailscale | static (overlay) | any site that is still online | real time for the other site's loss |

The LuCI page states which row applies, so nobody expects real-time alerts about an
internet outage the group cannot see out of.

### 4.9 Messages

Plain, one line where possible, no message without an event. Examples:

- `Home: ap-kitchen rebooted unexpectedly at 14:02, back after 1 min 5 s.`
- `Home: internet was down from 03:12 to 03:40 (28 min). Seen by gateway, ap-kitchen, ap-office.`
- `Home: gateway upgraded 25.12.4 -> 25.12.5 at 02:00, back after 3 min.`
- `Home: ap-office lost contact 14:02 to 14:05 but stayed up: a link problem, not a reboot.`

Message language: English in v1; templates kept in one file so translations can be
added.

Quiet hours and maintenance windows (v1.1, optional), an idea taken from heraldyx
v0.7.0: during quiet hours or a declared maintenance window non-critical incidents
are held and sent as one summary when the window ends; a router going silent or the
whole site losing internet is never held.

## 5. Packaging and release

- A new public repository `rollcall`, English, under TAIPANBOX (created only on
  the owner's go).
- Cross-compile in GitHub Actions; package with the `mkipk.sh` / `mkapk.sh` approach
  that openwrt-mcp already uses (an ipk is an archive; an apk v3 is written by
  `apk mkpkg` from a pinned alpine image; no OpenWrt SDK needed;
  `@source` openwrt-mcp `mkapk.sh`, verified there 2026-09-08 on 25.12.4).
- Targets: aarch64_cortex-a53, aarch64_generic, arm_cortex-a7, arm_cortex-a9,
  mipsel_24kc, mips_24kc (softfloat), x86_64.
- Releases on GitHub first, a signed feed later. Actions minutes on a public repo
  are free.
- `luci-app-rollcall` as a separate small package.

## 6. Testing

Tier T3 for group authentication and for sender election and delivery (a wrong
answer there is a silent missed alert); T2 for the rest.

- `features/*.feature`: scenarios from the asks of 2026-10-22, paraphrased (the repo
  is public), each bound to a named test by a binding gate. Draft list:
  - A member loses power: within 30 s another member reports it silent; on return it
    is reported as an unexpected reboot with the downtime.
  - The member that talks to Telegram loses its internet while another member has
    its own uplink: the other member takes over and reports it.
  - Nobody can reach Telegram for 20 minutes: after recovery one message reports the
    outage with start, end and duration, and nothing seen during it is lost.
  - A planned reboot and a crash are reported differently.
  - An upgrade is reported with the old and new versions.
  - A day without incidents leaves the chat empty.
  - A mesh node loses its radio link but stays up: reported as a link problem, not a
    reboot.
  - Separate routers, each with its own LAN and DHCP, form a group.
  - A single router works alone.
  - A device on the LAN that was never paired cannot inject events.
- Unit tests for classification, election, coalescing, de-duplication, catch-up.
- Fuzzing of the packet decoder; forged and replayed packets rejected.
- An in-process simulator: N members on a fake network with loss, delay, partition
  and a fake clock; a 200-seed sweep asserting: every incident delivered at least
  once after the network heals; no duplicate without a partition; never two pollers
  for longer than the backoff.
- Mutation testing on election, packet authentication and acknowledgement.
- Lab runs on Flint 2 and the two Beryl AX (never Brume 2): routers as they are
  wired today (separate LANs), two Beryl AX in an 802.11s mesh, one router behind
  another's NAT. Pull power, reboot, sysupgrade, unplug the sender's WAN, split the
  network.

## 7. Prior art

Targeted search on 2026-10-22: OpenWrt feeds (master, 25.12, 24.10), upstream
repositories, the OpenWrt forum, GitHub. Key claims re-checked against the primary
source the same day. Reddit returned nothing through search.

**Result: the exact pattern (routers of one site watch each other and whoever is
online reports to a person) was not found anywhere.** What exists covers pieces:

| What | Peer or central | Shares | Tells a person? | In OpenWrt feeds |
|---|---|---|---|---|
| mesh11sd (openNDS) | peer, every 802.11s node, "without a central controller" | mesh roles; moves the uplink (portal) role when a WAN drops | no | routing 7.3.1 (25.12) |
| apmond (openNDS, created 2026-10-21) | central collector | access point reports | not described | no |
| alfred | peer, batman-adv only | key/value facts over IPv6 link-local multicast; forgotten after 10 min | no | packages / routing |
| LibreMesh shared-state | peer, LibreMesh only | typed records over TCP 3490 | no | no (lime feed only) |
| usteer, DAWN | peer, one L2 | Wi-Fi client data between access points | no | yes |
| Gluon respondd + yanic | central collector | node info for maps | no | respondd only |
| keepalived (VRRP) | peer | who holds a virtual address; notify scripts | only through own scripts | yes |
| Netdata | per node, optional parent | metrics; sends Telegram itself | about itself only | 1.33.1, 27 MB installed (24.10) |
| OpenWISP, Zabbix | central server | fleet monitoring | from the server | agents yes |
| Telegram notifiers (luci-app-pushbot 453 stars, telegramopenwrt 142, about a dozen more) | one router each | its own state | yes | no |

Demand, from the forum (views / likes / posts on 2026-10-22):

- t/152401, Telegram bot to detect home power loss (2023): 2726 / 11 / 29. Accepted
  answer: the router sends a periodic message outside, silence means an outage.
- t/133076, "Router offline send notification" (2022): 1330 / 4 / 5. States the core
  problem: a router cannot report losing its own internet. Answers: an outside
  monitor, or a device with its own path (LTE stick, phone).
- t/128563, alert if a router behind double NAT dies (2022): 1006 / 1 / 7.
- t/152792, access points reporting to the main router (2023): 412 / 3 / 11. A senior
  forum member called inter-node communication hard and an implementation unlikely.
- t/254484, LuCI page listing all access points in a subnet (2026-10-15): 322 / 4 /
  18, open; replies point to apmond and to apcontroller (SSH polling from one box).

What this means for the design (`@claude`):

- The gap is real: per-node tools speak only for themselves; group tools are either
  central or tied to one mesh stack (batman-adv, LibreMesh), and none of them tells a
  person anything.
- Demand is steady but mid-sized (the top thread has 2.7k views), so v1 must be
  useful to a single router too (outage queue, report after recovery), with the
  group as the feature that sets it apart.
- Reuse the proven OpenWrt patterns instead of inventing: IPv6 link-local multicast
  for discovery (usteer, alfred), expiry by silence (alfred, DAWN), per-node daemon
  with no controller (mesh11sd).
- Coexist, do not compete: on a mesh11sd network, read its portal role as an event
  source later; with keepalived, optionally prefer the VRRP master as sender.
- Watch apmond: same author as mesh11sd, two days old, central collector today; it
  could grow towards this space.

## 8. Later modules (event sources in the same binary)

1. Upgrade keeper: snapshot of the package list and config, checks before upgrade,
   reinstall after it (the biggest community pain in the research).
2. Device list: merge DHCP names from the main router with Wi-Fi associations from
   the access points into one list (which device, which access point, what signal).
3. Wi-Fi advisor: occasional on-demand survey, channel recommendation.
4. Hub on x86: a member with more storage and history; optional.

## 9. Decisions on the open questions

`@decided 2026-10-22`, all four as proposed:

- Name: `rollcall`.
- Heartbeat every 5 s, silent after 30 s, internet lost after 3 failed probes 10 s
  apart.
- v1 sends notifications only; no chat commands.
- Messages in English; templates in one file for later translations.

The options as they were put:

1. Product name. Candidates checked on 2026-10-22 against the OpenWrt feeds (24.10
   index, 25.12 apk listing) and GitHub repository names (trademarks not checked):
   - `rollcall` (my pick: every router answers the roll call, a missing one is
     reported): no OpenWrt package, no GitHub repo combining it with OpenWrt; the
     largest same-name repo has 77 stars.
   - `wrtwatch`: no match anywhere; plainer.
   - `headcount`: no OpenWrt match; a same-name repo has 2080 stars.
   - Rejected: `witness` (the best-known repo of that name is a reconnaissance tool),
     `vigil` (about 24 800 repos, crowded).
2. Defaults: heartbeat 5 s, silent after 30 s, internet lost after 3 failed probes
   10 s apart.
3. Is `/status` in the chat needed in v1, or are push messages enough?
4. Message language in v1: English only, or English and Ukrainian.

Builder's calls (`@claude`): storage format; LuCI implementation details; exact
probe targets. Membership is now decided (own implementation).
