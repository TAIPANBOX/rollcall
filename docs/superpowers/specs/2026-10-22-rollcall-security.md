# rollcall: security architecture (approved 2026-10-22)

Companion to `2026-10-22-router-group-design.md`, which is approved. This document
defines how rollcall stays safe; the implementation plan follows only after it is
approved.

Provenance: `@decided 2026-10-22` paraphrases a decision taken that day; `@source`
marks a fact read from the named primary source on 2026-10-22; everything else is
`@claude` (my design, to be proven by the gates in section 12).

- `@decided 2026-10-22`: security is designed up front and written down in full, so
  that no hole appears later through which someone could get in or reach what they
  should not.
- `@decided 2026-10-22`: one primary admin router and one optional backup admin
  router, chosen by the owner; the admin list is extensible later (section 6.1).
- `@decided 2026-10-22`: when a split leaves two diverging rosters, the branch started
  with the higher authority wins (recovery key, then primary, then backup), and the
  changes of the losing branch are announced in the chat as undone (section 6.1).
- `@decided 2026-10-22`: history is a chain, not a list ordered by time, so that no
  router can overwrite another's data; routers that were down add their own part and
  check what was recorded without them (sections 5.7 to 5.9). v1 carries the
  per-router chains, witnesses, fork detection, the returning router's data and the
  reclassification of incidents; v1.1 adds checkpoints signed by a majority, late
  signatures from returning routers and objections with proof. The data format for
  v1.1 is fixed in v1.

## 1. What "secure" means for rollcall

1. **No new way in.** Installing rollcall must not give anyone outside the group a
   way to read, change or run anything on the router or in the network.
2. **Alerts cannot be faked or silenced from outside.** A device that is not a paired
   member can neither invent an event nor suppress a real one.
3. **Secrets do not leak** through packets, logs, LuCI, status output, or a router
   that was removed from the group.
4. **A lost, stolen or sold router can be cut off** without re-pairing the others.
5. **Failure is loud and closed.** If rollcall cannot run securely (missing or broken
   keys, invalid config, no sandbox), it does not run in a weaker mode; it says why,
   locally.

## 2. What we protect

| Asset | Why it matters | Where it lives |
|---|---|---|
| Telegram bot token | Anyone holding it can send messages as the bot (phishing the owner) and read the bot's updates | sender members only (section 8) |
| Group epoch key | Lets a holder read group traffic and pass the membership check | every member, rotated |
| Member identity keys (Ed25519 sign, ML-KEM768+X25519 receive) | Prove which member said what; receive new epoch keys | private part never leaves its router |
| Admin keys (primary, optional backup) | Sign the roster: who is in the group, with which roles | the two admin routers, one key each |
| Recovery key | Overrides both admins | offline only: the recovery code |
| Integrity of the history (per-router chains, checkpoints) and delivery state | A rewritten history hides what happened; a forged "delivered" mark is a silently lost alert | replicated on all members |
| The router itself | rollcall runs on the device that routes the whole network | n/a |
| Owner's privacy | router names, versions, outage times | members; Telegram receives them |

## 3. Who we defend against

| # | Adversary | Can | Assumption |
|---|---|---|---|
| A1 | Internet | send packets to WAN addresses | must have zero reachability to rollcall |
| A2 | Untrusted device on the LAN (guest, IoT, visitor laptop) | sniff, spoof IP/MAC, replay, flood the segment | the most likely attacker; full protocol defence |
| A3 | A member router that is lost, sold, or compromised | holds that member's keys, maybe the token | can lie as itself until removed; cannot impersonate others |
| A4 | Network path to Telegram/ntfy (rogue DNS, MITM) | redirect, intercept | TLS with certificate verification defeats it |
| A5 | Supply chain (dependency, CI, release download) | ship altered code | minimised, pinned, verified, signed |
| A6 | Local process or limited LuCI user on a router | talk to local interfaces | only root may administer rollcall |
| A7 | Someone holding a configuration backup file | read files from it | backups contain secrets; mitigated, not solved |

Out of scope: an attacker who is root on a member right now (rollcall limits what
that member can do to the others, and removal cuts it off); radio jamming (the
resulting silence is itself reported); Telegram's own security.

Trust boundaries: Internet | WAN zone of each router | the router (root, the
`rollcall` user, ubus, LuCI/rpcd) | the shared LAN segment (members and untrusted
devices side by side) | Telegram/ntfy over TLS.

## 4. Security decisions

1. **No inbound surface from the internet.** v1 is push-only: no webhook, no command
   handling, no `getUpdates` except the one-time chat binding (section 9). The UDP
   listener binds only to the interfaces of the configured peer zones; the firewall
   rule is scoped the same way.
2. **Two layers of cryptography.** Every packet is encrypted and authenticated with
   the current group epoch key (confidentiality plus "is a member"). Every message
   that changes state (event, acknowledgement, roster, epoch change) is additionally
   signed with its author's Ed25519 key (proves *which* member). A compromised member
   can only lie as itself.
3. **A signed, chained roster.** Membership and roles (`sender`, primary admin,
   backup admin) live in a versioned roster signed by an admin key; each version
   carries the hash of the previous one. Members accept only a newer version with a
   valid signature (no rollback) and compare the latest roster hash in heartbeats, so
   nobody can show different rosters to different members.
4. **Standard library cryptography only.** Go 1.27 standard library (`crypto/hpke`,
   `crypto/ed25519`, `crypto/ecdh`, `crypto/mlkem`, `crypto/hkdf`, `crypto/rand`) plus
   `golang.org/x/crypto/chacha20poly1305`. No custom primitives, no third-party crypto
   (`@source` `go doc` on Go 1.27.3: `crypto/hpke` implements RFC 9180 with
   `ChaCha20Poly1305`, `HKDFSHA256`, `MLKEM768X25519`; base mode, no PSK mode).
5. **Own minimal membership instead of hashicorp/memberlist.** For at most 32
   members a small heartbeat protocol is enough, and it keeps the dependency tree to
   the standard library and x/crypto. (This settles the builder's call left open in
   the design.)
6. **Least privilege on the router.** Dedicated user, no capabilities by default,
   `no_new_privs`, seccomp allow-list and ujail sandbox as hard package dependencies,
   ubus access limited by an ACL (section 7).
7. **The token goes only where it is needed.** Only members with the `sender` role
   receive the bot token. Access points with no uplink of their own never hold it.
8. **Plain text everywhere.** Telegram messages are sent without a parse mode and with
   link previews off; templates contain no links; strings that come from peers are
   length-limited and filtered; LuCI renders them as text, never as HTML.
9. **No command execution.** The daemon never starts a shell or another program
   (no `os/exec` in the daemon). Hotplug and init hooks talk to it through a Unix
   socket that checks the caller's credentials.
10. **Fail closed.** Missing keys, a corrupt roster, an invalid config or a missing
    sandbox stop the listener and show the reason in LuCI and syslog.
11. **Tamper-evident history.** Each member's events form its own signed hash chain;
    other members attach signed witness statements; forks are detected and proven
    (v1). Checkpoints signed by a majority fix the shared history (v1.1). Nothing is
    ever rewritten: corrections are new entries.
12. **People decide, not automation.** Roster changes, admin takeover and expelling a
    member are always run by root on a router. rollcall never expels a member on its
    own, because automatic expulsion would let a compromised router expel honest ones.

## 5. Protocol

### 5.1 Packet

`version (1) | flags (1) | epoch id (4) | nonce (24) | ciphertext + tag`, at most
1200 bytes. AEAD: XChaCha20-Poly1305 with a random 192-bit nonce (safe across reboots
without persisting a counter; fast in software on routers without AES hardware). The
header is authenticated as associated data.

Inside the ciphertext: sender member ID, boot sequence number, boot ID (128-bit
random), packet counter (64-bit, per boot), message type, body, and for state-changing
types an Ed25519 signature over all of the above plus the epoch id.

### 5.2 Order of checks, cheapest first

1. length and version; 2. epoch id known; 3. AEAD open; 4. replay check; 5. sender
present in the roster; 6. signature, for signed types; 7. schema and length limits of
every field; 8. handle.

Any failure: drop silently, count it, never reply. Unauthenticated input never causes
an outgoing packet (no reflection, no amplification, no oracle). Ed25519 verification
happens only after AEAD succeeded, so an outsider cannot make a router spend CPU on
signatures.

Flood handling: there is deliberately no blocking by source address, because an
attacker can spoof a member's address and would get that member muted. Instead every
packet gets the cheap AEAD check (at most 1200 bytes, microseconds), the daemon reads
at a bounded rate so its CPU use has a ceiling, and a burst of AEAD failures raises a
local `under_flood` event. If a flood still makes members look silent, that is
reported as an alarm, never hidden.

### 5.3 Replay

Each member keeps, per peer: the highest boot sequence number seen (a counter stored
on flash and increased once per boot: one write per boot), the current boot ID, and a
64-packet sliding window of counters. Packets from an older boot sequence, or outside
the window, are rejected. Wall clock time plays no part in replay protection, because
router clocks are not trusted after a power cut.

A member restored from an older backup starts with a lower boot sequence than its
peers remember. At start it asks the peers (an authenticated, signed request that
changes nothing on their side) for the highest number they saw from it and continues
above that, so a restore does not lock it out.

### 5.4 Transport

Heartbeats go over UDP (multicast for discovery, unicast to known peers). Larger
messages (join, roster, epoch key delivery, event catch-up) go over short TCP
connections between members on the same port, carrying the same encrypted and signed
messages as length-prefixed frames of at most 64 KiB; this is needed because a hybrid
ML-KEM key alone is over 1 KB. TCP limits: 8 concurrent connections, 5 s read deadline,
first frame must pass AEAD or the connection is closed.

### 5.5 Keys

- Identity, created on the router at first start, never exported: Ed25519 for
  signing; an HPKE `MLKEM768X25519` key pair for receiving key material (hybrid, so a
  recording of today's pairing traffic stays safe against a future quantum computer).
- Group epoch key: 32 random bytes created by the acting admin (6.1); packet keys derived with
  HKDF-SHA256 with a fixed label. Rotation: when a member is added or removed, on
  `rollcall rotate`, and every 30 days. During a switch the previous epoch is accepted
  for 60 seconds.
- Epoch keys are delivered to each member sealed with HPKE to that member's receive
  key and signed by the acting admin.
- **Every epoch key is bound to the roster it was issued under**: the delivery carries
  that roster's version and hash, the key's sequence number within that version and
  the issuing admin's place in that roster (primary or backup), all inside what the
  admin signs. Keys are ordered by that binding, never by the epoch id on the wire: a
  higher roster version first, then a higher sequence number, then the primary's key
  before the backup's. The sequence number starts again at 1 with every roster version
  and stops at 1023; at that cap rotation fails until the roster changes, so an admin
  that pushes it there blocks rotation only until the owner removes it. The epoch id
  in the packet header is 32 bits of a SHA-256 over the binding, the sequence number
  and the admin's place, so two admins on the two sides of a split never issue the
  same id.
- A member takes a delivered key only when it fits its roster: bound to its current
  roster, or to an earlier roster of its chain after which no member was removed,
  and signed by an admin whose place the key carries. Of two fitting keys it keeps
  the newer; a current key that no longer fits is replaced by a fitting one whatever
  the order. A key bound to a roster the member does not hold yet is kept aside and
  used only to fetch that roster from the admin who sent it; it is taken once the
  roster is. A key bound to a roster that lost a member since is refused. So a removed
  router never gets a key the rest of the group uses: the admin that signs the
  removal rotates at once, the acting admin rotates whenever its own key stops
  fitting (a removal signed elsewhere, by the recovery key for instance, or a split
  that healed in favour of the other branch), and a key the backup made on its side
  of a split, before the primary removed someone on the other side, does not fit the
  roster that wins. Other roster changes (roles, admins, a takeover) keep the key, so
  the two sides of a split that changed only roles still share a key when it heals.
  (Refined during implementation on 2026-10-23: this replaces epoch ids ordered as
  (sequence << 2) | authority, under which a removed admin could exhaust the sequence
  and a backup's key could outrank the primary's after a split.)
- A member that missed a switch for longer than the 60 s overlap still takes the new
  key: the delivery is sealed under the key it last used, and the admin reads its
  acknowledgement under that same key. A split during which both sides rotate (a
  removal on each side, or the 30-day rotation) and that outlasts the overlap leaves
  the two sides without a common key; they do not join again by themselves.

### 5.6 Roster

`{version, previous roster hash, site name, members: [{id, name, sign key, receive
key, roles}], admins: [primary, backup?] (ordered), recovery public key}`, signed by
an admin key or the recovery key. Limits: 32 members, `MaxAdmins` admins (one
constant, 2 in v1), exactly one primary, names up to 32 characters from a safe set. A
member that sees its own entry removed stops sending and clears its group secrets.

### 5.7 History: a chain per router (v1)

- Every entry a member records (an event, a witness statement, a correction) carries
  that member's next sequence number and the hash of its previous entry, and is
  signed by the member. No member can create a valid entry in another member's chain;
  deleting, changing or inserting an entry afterwards breaks the chain visibly.
- **Witnesses.** Other members add signed statements to an event in their own
  chains: "seen the same" or "seen differently". Messages show the count ("gateway
  silent, confirmed by 3 of 4"); an event claimed by one member while the others see
  the opposite is shown as exactly that. Delivery never waits for witnesses.
- **Fork detection.** A heartbeat carries the sender's own latest entry (sequence
  number and hash) and one digest over the latest entries it holds from all origins;
  the full list would not fit into 1200 bytes for 32 members. When two members'
  digests differ, they compare the per-origin heads over TCP and fetch what is
  missing. Two different signed entries with the same origin and sequence number are
  proof that the origin showed different histories to different peers. The origin is marked suspicious, the proof is kept, and an alarm goes to the
  chat.
- **Recording while cut off.** A member that is running but cannot reach the others
  keeps recording in its own chain with monotonic time; the entries spread when it
  is back.
- Cost: a 32-byte hash and a 64-byte signature per entry; flash writes stay batched.
  The log is bounded; older entries are folded into a signed summary (in v1.1, into a
  checkpoint).

### 5.8 A router coming back (v1)

When a member returns after a reboot, a power cut, a lost link or a lost internet
connection:

1. It publishes its own entries from the time it was away (if it was running) or its
   boot record.
2. It checks everything the others recorded about it against its own chain; on this
   it is the only member that knows the truth for certain.
3. The result is one of three, and they are kept apart on purpose:
   - **Agreement**: nothing to do.
   - **Honest difference**: the others saw it from another side. Example: three
     members recorded "ap-office silent, unplanned reboot", while ap-office shows the
     same boot ID throughout and a lost link. It appends a signed correction referring
     to the original entries; the incident is reclassified; one update goes to the
     chat only if the meaning of the incident changed ("ap-office did not reboot; its
     link was down").
   - **Proven falsehood**: a signed claim contradicts signed data, for example a
     reference to an entry it never produced, or a fork. The author is marked
     suspicious and the chat gets an alarm pointing at the proof. Whether to remove
     that member is the owner's decision.

Limit: a returning member can verify everything said about itself and the integrity
of the others' chains. It cannot verify what the others observed while it was away
(their internet probes, for instance). So "proven falsehood" is used only with a
signed contradiction, never for a mere difference in what was observed.

### 5.9 Checkpoints signed by a majority (v1.1)

- On automatically when the group has 3 or more members; with 2 members the chains of
  5.7 already give the protection a checkpoint could.
- Every 5 minutes and after every incident, the first live member by ID proposes a
  checkpoint: height, hash of the previous checkpoint, the latest signed entry of
  every member's chain (so it can only point at entries that really exist), and the
  roster hash.
- Members check it against what they hold and sign it. With signatures from more than
  half of the roster it is final: the history up to it can no longer be presented
  differently by anyone, admins included. Checkpoints link to each other by hash and
  form the shared chain.
- Too few members online: checkpoints pause and LuCI shows "finality paused: 2 of 5
  online". Alerts keep flowing; they never wait for a checkpoint.
- Honest arithmetic: a majority (3 of 5) survives two members being down but assumes
  the signers do not lie; a guarantee against one lying signer would need 4 of 5,
  which stops when two are down. rollcall uses the majority and makes lying
  provable: a member that signs two different checkpoints at the same height is
  caught with both signatures as proof (alarm, suspicious mark).
- **Late signatures.** A member that was away checks every checkpoint made without it
  (signatures, hash links, the heads it can check, above all its own) and adds its
  signature. The confirmation level grows, 3 of 5, 4 of 5, 5 of 5, and LuCI shows it.
  If it finds a proven falsehood, it publishes a signed objection with the proof, as
  in 5.8.
- The wire format for checkpoints, witness statements and objections is defined in v1,
  so v1.1 does not change the protocol.

## 6. Pairing and membership lifecycle

**init** (first router): creates the site, its own identity, the primary admin key,
the first epoch key, and a recovery key whose seed is printed once as the **recovery
code**. Only the recovery public key stays on the router; the owner keeps the code
offline. Admin roles are described in 6.1.

**join**:

1. On the admin router, `rollcall invite` (or the LuCI button) opens a join window for
   10 minutes and shows a join code: bootstrap address, the admin public key
   fingerprint, a 128-bit one-time join secret, expiry. The code is shown only to root
   and is copied by hand; it is never sent through Telegram or any network service.
2. The new router sends a join request: its identity public keys and name, encrypted
   and authenticated with a key derived from the join secret (HKDF), so only someone
   who holds the code can make a valid request.
3. The admin checks it, adds the member to the roster (role `sender` only if the owner
   ticks it), signs the roster, and replies with the roster, the current epoch key and,
   for senders, the bot token and chat ID, sealed with HPKE to the new member's
   receive key and signed by the admin key, which the new router checks against the
   fingerprint from the code.
4. The join secret is burned after one use or at expiry. Join requests are rate
   limited and accepted only while a window is open, on the peer zone only, over the
   TCP transport of 5.4.

**remove** (lost, sold, replaced router): `rollcall remove <name>` on an admin. New
roster without it, new epoch key sealed to every remaining member. The removed router
can no longer read or inject anything. If it was a sender, LuCI and the CLI tell the
owner to revoke the token in @BotFather and run `rollcall set-token`; this step cannot
be automated because BotFather has no API for it.

**rotate**: new epoch key at once (after sharing a backup, or on suspicion).

**admin lost**: see 6.1.

**factory reset or new device**: it is a new member; join again. Restoring a backup on
a second device clones an identity; two live members with the same ID and interleaved
boot sequences raise a `duplicate_identity` alert.

### 6.1 Admin roles

- The owner picks in LuCI: one **primary admin** router and, optionally, one **backup
  admin** router. All others are ordinary members. The admin list in the roster is
  ordered and limited by one constant, `MaxAdmins` (2 in v1), so the limit can be
  raised later without a redesign.
- Each admin creates its own admin key on its own router; no admin key is ever copied
  (a dead router could not hand its key over anyway). The recovery key is separate and
  offline.
- **Powers.** Both admins can change the roster (invite, remove, set roles, appoint or
  replace the backup) and rotate the epoch key. Routine duties, such as the 30-day
  rotation, are done automatically by the first live admin in the list, the same way
  the sender is chosen. The recovery key overrides both: it can appoint a new primary
  and backup and remove any member.
- **Takeover.** If the primary is gone, root on the backup runs `rollcall admin
  takeover`. A member accepts the takeover only if it has itself heard nothing from
  the primary for at least 10 minutes; members that still hear the primary reject it.
  So a compromised backup cannot take over while the primary is alive and reachable.
  A takeover is provisional: if the former primary comes back, it restores itself as
  primary with the next roster version (announced in the chat), unless the owner has
  confirmed the takeover or has used the recovery code. A confirmation made as root on
  the backup takes effect only after a day: a member accepts it only when it has itself
  heard nothing from the replaced primary for at least 24 hours, so a primary that
  returns within that day still restores itself and the pending confirmation lapses.
  The backup holds a confirmation made earlier and announces it once its own day of
  silence has passed. A backup therefore cannot keep the role by cutting the primary
  off for ten minutes: it would have to cut it off from every member for a whole day
  while the takeover stands announced in the chat. The recovery code confirms at once.
  A takeover and its confirmation signed together in one roster version wait for the
  same day. A member counts the day from its own start at the latest, so a restart
  starts it again; the backup keeps a held confirmation on flash, and the CLI says it
  is held. A lapse is never told in the chat. The replaced
  primary itself takes the confirmation of its replacement when it comes back, as it
  takes the takeover.
  @decided 2026-10-23: a confirmation by root on the backup waits for a day of silence
  from the replaced primary; a confirmation that needs the recovery code was weighed and
  not chosen, because it adds an owner step and puts the recovery code to routine use.
- **Conflicts.** If the network splits and both sides change the roster, after healing
  the branch whose first roster after the split was signed with the higher authority
  wins: recovery key, then primary, then backup, judged against the last roster both
  sides shared. A branch belongs to whoever started it, so a branch the primary started
  keeps the primary's rank even when a backup it appointed on that side signs its later
  rosters. At equal authority the branch whose newest roster has the higher version
  wins, then the lower hash of that newest roster. Authority comes first so that a
  compromised backup cannot win by making many changes during the split. Changes from
  the branch that lost are not dropped silently: the chat gets one message listing what
  was undone and which router made it, so a person can repeat what was wanted.
  (Refined during implementation on 2026-10-22; the first draft ranked the version
  first. Refined again on 2026-10-23: the version is read from each branch's newest
  roster, since the first rosters of two branches always share one version.)
- **Visibility.** Every roster change, role change and takeover is announced in the
  chat with the name of the router that signed it ("ap-office removed by admin
  gateway"). If an admin router is taken over by an attacker, its changes are seen at
  once.
- **Both admins lost, or one suspected compromised.** Root on any member runs
  `rollcall admin recover` with the recovery code: it appoints a new primary (and
  backup), removes the suspect if needed, and the epoch key rotates.
- Shape check: exactly one primary, at most `MaxAdmins` admins, exactly one recovery
  public key; a roster of any other shape is rejected.

## 7. Hardening on the router

| Control | Mechanism | Source / note |
|---|---|---|
| Own user | `procd_set_param user rollcall` (and group) | `@source` procd.sh supports `user`, `group` |
| No privilege gain | `no_new_privs`, set by procd and again by the daemon before it installs its filter | `@source` procd.sh |
| No capabilities | empty capability set; ICMP probes are off by default (DNS and TCP 443 probes need none); enabling ICMP adds `CAP_NET_RAW` only | `@source` procd.sh supports `capabilities` |
| System call allow-list | the daemon installs its own seccomp filter at start, from the per-architecture list the package ships: right after the command line and before it opens any file or socket, `no_new_privs`, then a classic BPF program (a call of another architecture killed, the listed calls allowed, any other kills the process) installed with `SECCOMP_FILTER_FLAG_TSYNC` on every thread; it refuses to run when that fails and to listen unless the kernel shows `Seccomp: 2`. The same lists produce `/etc/seccomp/rollcall.json`, a readable record that procd does not load; a gate keeps both equal per target. procd's `seccomp` parameter is not used: procd applies it through `LD_PRELOAD=/lib/libpreload-seccomp.so`, which a statically linked program never loads. `procd-seccomp` stays a hard dependency (section 14) | lab run 2026-10-23: under procd's parameter the daemon read `Seccomp: 0` on 25.12.5 |
| Sandbox | ujail: read-only root, writable only `/etc/rollcall`, `/var/run/rollcalld` and `/var/run/rollcall`; read-only `/etc/config/rollcall`, the release file, certificates, zone data and resolver files; never `/etc/config/network`, `system` or `firewall`, nor a directory holding them; `procd-ujail` is a hard dependency (about 110 KiB) | `@source` procd.sh `_procd_add_jail`, 24.10 index |
| Root-only configuration | network and system are mode 0600 root on 25.12 and may hold PPPoE passwords and WireGuard private keys, so the daemon never reads them: root (`rollcall snapshot`, run by the init script before each start and by the interface hotplug) parses network, firewall and system and writes only the zones, their devices, which zones face the internet and the time zone to `/var/run/rollcall/snapshot.json`, root:rollcall 0640; the daemon refuses to start when the snapshot is missing, malformed or older than those files, and never falls back to them | lab run 2026-10-23: the daemon could not open network on 25.12.5 |
| ubus | ACL `/usr/share/acl.d/rollcall.json`: listen to `network.interface` events, call read-only `network.interface` status and `system` info, nothing else | `@source` ubusd_acl.c reads `/usr/share/acl.d` with user, access, listen, send |
| Files | `/etc/rollcall/` 0700 owned by `rollcall`; key files 0600. Secrets never in UCI, so `uci show` and LuCI never see them | |
| Control socket | `/var/run/rollcall.sock`, 0660 root:rollcall; `SO_PEERCRED`: only uid 0 may run admin commands; hooks run as root | |
| LuCI | rpcd ACL with two levels: read status, and administer (invite, remove, rotate, set token) | |
| Outbound | in code: only Telegram or the configured ntfy host, configured probe targets, roster peers | |
| Firewall | one firewall4 rule from the package: UDP and TCP, rollcall port, source = configured peer zones (default `lan`); for static peers in the WAN zone (cascaded NAT) also `src_ip` limited to those peers; removed on uninstall | binding to specific interfaces without extra capabilities: verify on hardware |
| Limits | UDP packet 1200 B, TCP frame 64 KiB, 8 TCP connections, roster 32, event log 500, catch-up paced | |
| Updates | no self-update, no telemetry, no phoning home | |

The sandbox and seccomp behaviour must be proven on 24.10 and 25.12 hardware before
release; if a target cannot run them, that target is not shipped rather than shipped
without them.

## 8. Secrets: where they live and how they leave

| Secret | Stored | Held by | In a system backup? | Rotation |
|---|---|---|---|---|
| Bot token, chat ID | `/etc/rollcall/secrets` 0600 | sender members only | yes | revoke in BotFather, `set-token` |
| Group epoch key | `/etc/rollcall/` | all members | yes | automatic every 30 days, on removal, `rotate` |
| Identity private keys | `/etc/rollcall/` | that member only | yes | re-join |
| Admin keys | `/etc/rollcall/` on the primary and the backup admin | one key per admin router | yes | if one leaks or is suspected: recovery code appoints a new admin and removes the old one |
| Recovery key | nowhere on the routers after `init`; printed once | the owner, offline | no | if lost together with both admins: new site, every router joins again |
| Join secret | RAM only | admin, for 10 minutes | no | single use |

System backups (`sysupgrade -b`) include every file listed in `/lib/upgrade/keep.d`
(`@source` base-files `sysupgrade`), and rollcall must list its directory there to
survive upgrades. So a backup file is as sensitive as a password. The rollcall LuCI
page says this plainly, and `rotate` is one click away.

Redaction: the token and keys never appear in logs, status output, LuCI responses or
crash output. A test plants a canary token and searches every output path for it.

## 9. Telegram and ntfy

- HTTPS only, certificate verification always on (system `ca-bundle`, a package
  dependency); the Telegram host is fixed to `api.telegram.org`.
- Chat binding at setup: rollcall shows a one-time code; the owner sends exactly that
  code to the bot in a private chat; rollcall polls `getUpdates` for at most 10
  minutes and accepts only a private chat whose message equals the code. It then
  stores the chat ID, clears the update queue and never polls again. Messages from any
  other chat are ignored, so nobody can hijack the binding by messaging the bot first.
- Push only afterwards; nothing the bot receives is read or acted on in v1.
- No parse mode, link previews off, fixed templates without links, peer strings
  filtered. The README states: rollcall never sends links and never asks you to do
  anything; a message from the bot that does is not from rollcall.
- At most one message per second per chat; incidents are coalesced (design 4.3).
- If TLS fails (rogue DNS, interception), the incident stays queued, nothing is sent
  in clear, and LuCI shows "cannot reach Telegram securely".
- ntfy: HTTPS by default; plain HTTP only to private or link-local addresses with an
  explicit `allow_insecure_lan` option; an ntfy access token is stored like the bot
  token.
- What leaves the site: site name, router names, event types, times, OpenWrt
  versions. No client devices in v1. The README says so.

## 10. Supply chain and releases

- Dependencies: the Go standard library and `golang.org/x/crypto` (plus `x/sys` if
  needed). A gate fails the build on any other module. `go.sum` committed; `go mod
  verify` and `govulncheck` block CI.
- Build: `CGO_ENABLED=0`, `-trimpath`, fixed `-ldflags`; two independent CI builds of
  a tag must produce identical binaries.
- CI: actions pinned by commit SHA, job-level least permissions, no secrets in pull
  request workflows, release only from a tag, secret scanning before every push.
- Releases: `SHA256SUMS` signed; a signed OpenWrt feed later (as hermes-openwrt has);
  an SBOM per release.
- `SECURITY.md` with private vulnerability reporting through GitHub.

## 11. Threats and what stops them

| # | Threat | Stopped by | Result |
|---|---|---|---|
| 1 | LAN device injects a fake "router down" or "internet lost" | AEAD with the epoch key | dropped |
| 2 | LAN device replays captured packets (for example an old "going down") | boot sequence, boot ID, counter window | dropped |
| 3 | LAN device sniffs to map the infrastructure | payload encrypted; only version, epoch id and nonce visible | it learns that rollcall runs, nothing more |
| 4 | LAN flood on the port | cheap AEAD check first, bounded read rate, `under_flood` event | CPU bounded; if members still go silent, that is reported |
| 5 | Spoofing a member's IP | AEAD; no blocking by source address, so a spoofed address cannot get a member muted | no effect |
| 6 | Anything from the internet | nothing listens there; firewall scoped to peer zones | no surface |
| 7 | Someone messages the bot | v1 never reads updates after setup | ignored |
| 8 | Hijacking the chat binding at setup | one-time code, private chat only | rejected |
| 9 | A member forges events or acks as another member | Ed25519 signature per author | rejected |
| 10 | A compromised sender abuses the token | token only on senders; BotFather revoke; templates never contain links | residual, see 13 |
| 11 | Lost or sold router | `remove`, new epoch key, token revoke if sender | cut off |
| 12 | Leaked backup file | `rotate`; LuCI warning | residual for the time before rotation |
| 13 | Backup restored onto a second device | `duplicate_identity` alert | detected |
| 14 | Hostile strings from a member (LuCI script injection, chat formatting) | text-only rendering, plain-text messages, filters | inert |
| 15 | Parser bug | memory-safe Go, size limits, schema checks, fuzzing | contained |
| 16 | Local non-root process uses the control socket | `SO_PEERCRED`, uid 0 only for admin | rejected |
| 17 | Limited LuCI user triggers admin actions | rpcd ACL split | rejected |
| 18 | MITM or rogue DNS towards Telegram | TLS verification; fail closed, keep queue | nothing leaks, nothing lost |
| 19 | Protocol downgrade | version in authenticated header; minimum version enforced | rejected |
| 20 | Compromised dependency or CI | minimal dependencies, pinned actions, govulncheck, reproducible builds, signed releases | made hard and detectable |
| 21 | Admin router lost | the backup admin takes over; the recovery code if both are lost | recovered |
| 22 | Rogue NTP on the LAN | time is not used for security; members cross-check clocks and mark large disagreement as approximate | only displayed times affected |
| 23 | A compromised admin router rewrites the roster | every change announced in the chat with its signer; chained roster prevents different versions for different members; recovery key overrides | seen at once; the owner cuts it off |
| 24 | The backup admin tries to take over while the primary is alive | members accept a takeover only after 10 minutes of silence from the primary; at equal versions the primary wins | rejected |
| 25 | A member shows different histories to different peers | per-member hash chains; heads compared in every heartbeat | caught with proof |
| 26 | A member rewrites or deletes its own past entries | hash chain breaks; peers hold copies | caught |
| 27 | A checkpoint points at an entry its owner never produced (v1.1) | checkpoints carry each member's signed latest entry; the returning member checks its own | caught with proof |
| 28 | A member signs two different checkpoints at one height (v1.1) | both signatures kept as proof | caught |
| 29 | A compromised member tries to get honest members expelled | no automatic expulsion; the owner decides | no effect |

## 12. Invariants and the gate that will hold each

Each becomes a named invariant in the repo's CLAUDE.md with its gate, and each gate
gets a case in `scripts/gates-have-teeth.sh`. Mutation testing (T3) covers 2, 3, 4,
5, 9, 14, 15, 17 and 19.

1. Nothing listens outside the configured peer zones (test: config validator and an
   integration test that lists sockets).
2. No packet content is processed before AEAD succeeds, and unauthenticated input
   never produces an application-level reply (fuzz test plus a "zero bytes sent"
   assertion; mutant: skip the AEAD check, tests must go red).
3. Replays are rejected (test with a captured-packet corpus).
4. State-changing messages without a valid author signature are rejected (test and
   mutant).
5. The roster only moves forward and only with an admin signature (test and mutant).
6. Secrets never appear in any output (canary test).
7. The daemon does not import `os/exec` (gate on the import graph).
8. Only the allowed modules are dependencies (gate on `go.mod`).
9. TLS verification is never disabled (gate forbids `InsecureSkipVerify`; mutant).
10. Telegram requests carry no parse mode (test).
11. A member without the `sender` role never holds the token (pairing test).
12. Missing or corrupt keys stop the listener (test).
13. The service file sets the user, `no_new_privs` and the jail (gate on the init script);
    the daemon installs its own seccomp filter, from the list the package ships, before it
    opens any file or socket, on every thread, and does not run without it (gates on the list
    and on `main`, tests that a forbidden call kills the process); the router run proves it
    (lab run).
14. A roster has exactly one primary, at most `MaxAdmins` admins and exactly one
    recovery key; any other shape is rejected (test and mutant).
15. A takeover is accepted only by a member that has not heard the primary for 10
    minutes, and a returning primary restores itself unless the owner confirmed the
    takeover or used the recovery code (test and mutant).
16. Every roster change produces exactly one chat announcement (test).
17. An entry whose previous hash does not match its chain is rejected, and two
    different signed entries with the same origin and sequence raise the fork alarm
    (test and mutant).
18. The history store is append-only: corrections never modify existing entries
    (test).
19. (v1.1) A checkpoint is final only with signatures from more than half of the
    roster, and an honest member never signs two different checkpoints at one height
    (test, mutant, and a 200-seed simulator sweep with members down and one liar).

## 13. Residual risks, said plainly

- A member that is fully compromised while still in the group can lie about its own
  state and delay its own acknowledgements; if it is a sender it can send anything
  through the bot until it is removed and the token revoked in BotFather.
- A compromised admin router can change the group until the owner reacts; every
  change is announced in the chat, and the recovery code overrides it.
- With majority checkpoints a lying signer is caught, not prevented.
- A member that was away cannot verify what the others observed in the meantime;
  only claims about itself and the integrity of the chains.
- System backup files contain rollcall's secrets.
- Telegram sees router names and outage times.
- A flood or radio jamming can make members look silent; this produces an alarm, not
  a hidden failure.
- This is a design. Nothing in it is proven until the gates, the fuzzing and the lab
  runs in section 12 exist and pass.

## 14. Decisions on the open questions

`@decided 2026-10-22`, approved together with this document:

1. Secrets stay in the upgrade and backup set, so upgrades survive; the LuCI page
   warns that a backup file is as sensitive as a password, and rotation is one click.
2. The sandbox packages (`procd-seccomp`, `procd-ujail`) are hard dependencies; a
   target that cannot run them is not shipped.
   `@claude 2026-10-23`, beside the decision and not changing it: procd-seccomp cannot filter
   rollcalld, which is statically linked (procd applies a profile through `LD_PRELOAD`), so the
   daemon installs its own filter (section 7) and the init script no longer asks procd for one.
   The dependency stays as decided; nothing of rollcall uses it now, and dropping it would be a
   decision of its own.
3. Admin recovery: an optional backup admin router plus the offline recovery code
   (section 6.1).
