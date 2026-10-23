# rollcall output for LuCI

This file is the contract between the `rollcall` CLI and the LuCI app. The
status page and the admin page read exactly the fields written here and
nothing else. The CLI (Task 21) prints exactly these shapes. A change to a
field is a change to this file, and both sides move together.

Schema version: `1`. Every status report carries `"schema": 1`. The page
refuses any other value and says so.

## How the pages call the CLI

Both pages run the CLI through rpcd `file.exec`, with the command
`/usr/bin/rollcall` and the arguments below. rpcd allows only the exact forms
in `root/usr/share/rpcd/acl.d/luci-app-rollcall.json`.

| Group | Arguments | Used by |
|---|---|---|
| `luci-app-rollcall` (read) | `status --json` | status page, admin page |
| `luci-app-rollcall-admin` (write) | `invite --json` | admin page |
| | `invite --json --sender` | admin page: the new router gets the sender role |
| | `invite --json -- <address>` | admin page: the join code names this address |
| | `invite --json --sender -- <address>` | admin page: both |
| | `remove --json -- <name>` | admin page |
| | `rotate --json` | admin page |
| | `set-token --json` | admin page (token in the environment, see below) |
| | `bind-telegram --json` | admin page |
| | `roles --json sender\|primary\|backup\|none -- <name>` | admin page |
| | `admin takeover --json` | admin page, backup admin only |
| | `admin confirm --json` | admin page, while a takeover is provisional |

The admin group also carries the read entry, because the admin page reads the
status too.

## Rules for every output

- One JSON object on stdout. Nothing else on stdout.
- Times are RFC 3339 in the router's configured time zone.
- Strings are plain text. The page never interprets markup, but the CLI must
  not send any either.
- Never present in any output: the bot token, the group key, a join code
  (except in the reply to `invite`), a bind code (except in the reply to
  `bind-telegram`), the recovery code, the chat ID. Redaction applies to error
  text too.

## `rollcall status --json`

Exit status 0 when it printed a report, 1 when the daemon is not running.
The page reads stdout whatever the exit status.

Daemon not running:

```json
{"schema": 1, "running": false, "error": "rollcalld is not running"}
```

Not set up yet (no group on this router):

```json
{"schema": 1, "running": true, "initialised": false}
```

A set-up router prints every field below.

| Field | Type | Values and meaning |
|---|---|---|
| `schema` | integer | `1` |
| `running` | bool | `true` when `rollcalld` answers on the control socket |
| `initialised` | bool | `true` once `init` or `join` has run |
| `generated` | time | when the report was made |
| `site` | string | the group's site name, as in the messages (`Home`) |
| `self` | object | this router, see below |
| `confirmation` | object or null | a confirmation of a takeover made on this router that is held or lapsed, see below; `null` when there is none |
| `members` | array | the roster, this router included, at most 32 entries |
| `sender` | string or null | name of the member that sends to Telegram now; `null` when no member can reach Telegram |
| `incidents` | array | newest first, at most 20 entries, see below |
| `discovery` | array | one entry per interface where discovery failed; `[]` when none |
| `topology` | string | `no_second_uplink`, `second_uplink` or `overlay_sites`, see below |
| `sandbox` | object | the state of the daemon's own sandbox, see below |
| `storage` | object | `{"ok": bool, "error": string or null}` |
| `telegram` | object | this router's Telegram state, see below |
| `group_key` | object or null | `null` before the first key exists |
| `backup_warning` | bool | `true` when this router holds the group key, so its configuration backup holds secrets |
| `under_flood` | bool | `true` while this router receives a burst of packets that fail authentication (security design 5.2); local status only, never a chat message, see below |

### `self`

```json
{"name": "gateway", "roles": ["sender", "primary"], "admin": "primary", "takeover": false}
```

- `name`: this router's name (`[a-z0-9-]`, at most 32 characters).
- `roles`: zero or more of `sender`, `primary`, `backup`. `[]` for an ordinary member.
- `admin`: `"primary"`, `"backup"` or `null`.
- `takeover`: `true` while a takeover by the backup admin is provisional and not
  yet confirmed.

### `confirmation`

```json
{"state": "held", "of": "gateway", "from": "2026-10-24T10:00:00+01:00"}
```

A takeover confirmed with `admin confirm` before the replaced primary has
been silent for a day is held on this router and takes effect once the day
has passed (security document, section 6.1). The field is `null` when this
router holds no confirmation and none lapsed.

- `state`: `held` while it waits, `lapsed` when the replaced primary was heard
  before the day was over, or the takeover ended (the primary restored itself,
  or the recovery key decided). A lapsed confirmation stays reported until the
  next one is held.
- `of`: the replaced primary's name while `held`; `null` when `lapsed`, or
  when the roster no longer names it.
- `from`: the earliest time the confirmation takes effect, while `held`: a day
  after the replaced primary was last heard, or after this router's start when
  that is later, so a restart moves it later; `null` when `lapsed`.

### `members`

```json
{"name": "ap-office", "roles": [], "state": "silent", "last_seen": "2026-10-23T14:00:00+01:00", "last_seen_seconds": 125}
```

- `state`: `up`, `suspect` (missed heartbeats, not yet silent), `silent`,
  `suspicious` (a fork proof is on record for this member), `unheard` (in the
  roster but not heard from since this boot).
- `last_seen`: time of the last authenticated packet, or `null` when not heard
  since this boot. For this router, `last_seen` is `generated` and
  `last_seen_seconds` is `0`.
- `last_seen_seconds`: whole seconds before `generated`, or `null`.

### `incidents`

```json
{"id": "3f9c1a", "time": "2026-10-23T13:00:00+01:00", "text": "Home: ap-kitchen rebooted unexpectedly at 14:02, back after 1 min 5 s.", "confirmed_by": 3, "members": 4, "delivered": true}
```

- `id`: short incident ID, the same one the chat message carries.
- `time`: when the incident started.
- `text`: the line the chat gets, as plain text.
- `confirmed_by`: how many members' signed histories agree with the event,
  this router included.
- `members`: how many members the roster had when the count was taken.
- `delivered`: `true` when the chat has the message, `false` while it waits.

### `topology`

Which row of the topology table in the design applies to this group:

- `no_second_uplink`: no member has its own uplink independent of the main
  line (one router, one shared segment, a mesh, a routed mesh, cascaded NAT
  with no second uplink). Outage reports arrive after recovery.
- `second_uplink`: at least one member has its own second uplink, so an outage
  of the main line can be reported as it happens.
- `overlay_sites`: several sites joined over WireGuard or Tailscale. A site
  that stays online reports the other site's loss as it happens.

The page maps each value to its wording. The CLI sends the value only.

### `sandbox`

```json
{"state": "enforced", "no_new_privs": true, "seccomp": true, "jail": true}
```

- `state`: `enforced` when all three flags are true, `partial` when some are
  false, `off` when the daemon runs without its sandbox (it refuses to start
  in that case, so `off` should be rare).

### `telegram`

```json
{"state": "bot_blocked", "last_ok": null}
```

- `state`:
  - `ok`: this router's last reachability check of the bot succeeded.
  - `not_configured`: no bot token exists for the group.
  - `not_sender`: this router holds no bot token; a sender sends for the group.
  - `not_bound`: the token is set but no chat is bound yet.
  - `bot_blocked`: Telegram answered 403; messages wait in the queue.
  - `rate_limited`: Telegram answered 429; messages wait for `retry_after`.
  - `tls_failed`: the certificate check failed; messages wait in the queue.
  - `unreachable`: no successful call within the last 60 seconds.
- `last_ok`: time of the last successful call on this router, or `null`.

No raw error text ever goes into this object. Every state is one of the words
above.

### `under_flood`

`true` while packets that fail the authenticated decryption keep arriving in a
burst; it goes back to `false` once no burst has been seen for a while. The
packets are dropped and nothing is blocked by source address, so a member
whose address is spoofed keeps working. A flood that makes members look
silent still shows as `silent` members and as an alarm. The page shows a
warning while it is `true`; the chat never hears of a flood.

### Example of a full report

```json
{
  "schema": 1,
  "running": true,
  "initialised": true,
  "generated": "2026-10-23T14:02:05+01:00",
  "site": "Home",
  "self": {"name": "gateway", "roles": ["sender", "primary"], "admin": "primary", "takeover": false},
  "confirmation": null,
  "members": [
    {"name": "gateway", "roles": ["sender", "primary"], "state": "up", "last_seen": "2026-10-23T14:02:05+01:00", "last_seen_seconds": 0},
    {"name": "ap-office", "roles": [], "state": "silent", "last_seen": "2026-10-23T14:00:00+01:00", "last_seen_seconds": 125}
  ],
  "sender": "gateway",
  "incidents": [
    {"id": "3f9c1a", "time": "2026-10-23T13:00:00+01:00", "text": "Home: ap-office went silent at 13:00.", "confirmed_by": 2, "members": 2, "delivered": true}
  ],
  "discovery": [],
  "topology": "no_second_uplink",
  "sandbox": {"state": "enforced", "no_new_privs": true, "seccomp": true, "jail": true},
  "storage": {"ok": true, "error": null},
  "telegram": {"state": "ok", "last_ok": "2026-10-23T14:02:01+01:00"},
  "group_key": {"created": "2026-10-01T03:00:00+01:00", "age_days": 22, "rotates_every_days": 30},
  "backup_warning": true,
  "under_flood": false
}
```

## Admin commands: the reply

Every admin form prints one JSON object and exits 0 on success, 1 on failure.

Success:

```json
{"ok": true, "message": "Join window open for 10 minutes."}
```

Failure:

```json
{"ok": false, "error": "no such member: ap-foo"}
```

Optional keys on success:

- `join_code` (`invite` only): the one-time join code. It works once, for 10
  minutes. The page shows it in a dialog to the admin and keeps it nowhere.
  `rollcall join` on the new router reads it from standard input, never from
  its command line, which every process on that router can read.
- `bind_code` (`bind-telegram` only): the code the owner sends to the bot in a
  private chat within 10 minutes. Shown in a dialog, kept nowhere.

Messages and errors are plain English sentences.

### Specific rules

- `set-token` reads the bot token from the environment variable
  `TELEGRAM_ROLLCALL_TOKEN`. It never takes the token as an argument, so the
  token does not appear in a process list. The reply never repeats the token.
- Name arguments come last, after `--`. Options come before it. The name is the
  only glob in each admin entry, and the entries fix the order:
  `remove --json -- <name>` and `roles --json <role> -- <name>`. The CLI accepts
  exactly one name after `--`, checks it with the roster name rule
  (`[a-z0-9-]`, at most 32 characters) and rejects anything else. The page passes
  a name it read from the status report.
- `invite` takes the address the new router reaches this router at in the same
  place: alone after `--`, the only glob of its entries. The CLI accepts exactly
  one word there and refuses anything but one IP address another router can
  reach (no zone; not loopback, link-local, multicast, broadcast or
  unspecified). Without it the CLI picks the first address of the peer zones,
  which a router at another site may not reach. `--sender` gives the new router
  the sender role, only when the admin ticks it.
- `admin takeover` is provisional until `admin confirm` runs, as in the
  security document, section 6.1.

## Open points

These are not settled by this file. Each one is checked on hardware or decided
by the controller.

1. rpcd argument matching. The ACL keys name the full command line
   (`/usr/bin/rollcall roles --json sender -- *`). That matching must be confirmed
   on a router with rpcd of the target release (Task 27, step 2). If rpcd
   matches only the path, the ACL has to be narrowed another way before the
   admin group is shipped.
2. The `env` parameter of rpcd `file.exec`, used by `set-token`, must be
   honoured by rpcd on 24.10 and 25.12. Confirm on hardware.
3. Recovery is CLI-only. Root on a router runs `rollcall admin recover` with the
   recovery code. The LuCI ACL has no entry for it and no page offers it, so the
   code never reaches rpcd or a LuCI request. Task 21 still decides how the CLI
   reads the code; standard input is preferred over an argument, so the code
   stays out of the process list.
4. The admin group carries the read entry, so the admin page can read the
   status with that group alone. The parent menu item lists both groups. How
   LuCI treats several groups in one `depends` list (any one of them, or all)
   is not verified here; check it on the lab router.
