# rollcall attest: a signed answer to an outside auditor

An auditor that reads a router's signed history over SSH learns what the router signed, but
nothing it reads answers a question of its own: a copy of the files taken a week ago reads the
same. `rollcall attest` closes that: the auditor sends a fresh nonce, and the router signs, with
its member key, a statement of its state over that nonce.

`@decided 2026-11-08`: rollcall gets a command that signs a statement of the router's state over a
nonce an outside auditor chose, with the member key, under a signature domain of its own, and that
writes nothing to the router's flash.

## The command

```sh
rollcall attest --nonce <hex>
```

- Runs as root only; another user is refused before anything is read.
- The nonce is 16 to 64 bytes, given as 32 to 128 hex digits (either case, nothing else: no `0x`,
  no spaces). Anything else is a usage error (exit 2, or exit 1 with `--json`), refused before the
  key, the history or the kernel's boot ID is read.
- It reads the member key from `/etc/rollcall/identity.json` with the checks the daemon's start
  makes (no access for group or others, a regular file whose keys match each other), and the
  router's own chain from `/etc/rollcall/history-<member id>.json`, which it verifies whole
  before it takes anything from it. A chain that does not verify is not vouched for: exit 1.
- It writes nothing: no file, no temporary file, no state. An auditor may ask every hour.
- It works whether `rollcalld` runs or not. The router's own entries reach the history file before
  the daemon takes them, so the head it signs is the newest the router has made.
- On success it prints one line of JSON on standard output and exits 0. Errors go to standard
  error, exit 1.

## The output

```json
{"schema":1,"nonce":"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff","member":"00112233445566778899aabbccddeeff","head":{"seq":42,"hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"kernel_boot_id":"4e7c1b2a9d3f40e8b5a6c7d8e9f00112","boot":{"id":"4e7c1b2a9d3f40e8b5a6c7d8e9f00112","seq":7,"openwrt":"25.12.4"},"rollcall":"1.0.0-rc2","time":"2026-11-08T12:00:00Z","sig":"384f30a0c33980c035f299d008cca53cbc591298f7564c39d425530b68c48f43da7de68154f01e0f41f8f0ec0bae68d49330385a570d6ba157f3c0a1899dfe05"}
```

| Field | What it holds |
|---|---|
| `schema` | `1`. It goes with the signature kind `attest`; a later format takes another kind and another number. |
| `nonce` | the caller's nonce, lowercase hex, 16 to 64 bytes |
| `member` | the member ID, 16 bytes in lowercase hex |
| `head` | the head of the router's own chain: `seq` and the entry `hash` (SHA-256, as the next entry's `prev` carries it). `seq` 0 and an all-zero hash when the chain is empty. |
| `kernel_boot_id` | `/proc/sys/kernel/random/boot_id` at the moment of the statement, as 16 bytes in lowercase hex (the hyphens dropped) |
| `boot` | from the newest boot record in the chain: the boot `id` it names, its boot sequence number `seq` (one more on each boot) and the OpenWrt release `openwrt` it was written on. All zero and `""` when the chain holds no boot record. |
| `rollcall` | the version of the `rollcall` that signed |
| `time` | the router's wall clock, RFC 3339 in UTC, whole seconds |
| `sig` | the Ed25519 signature, 64 bytes in lowercase hex |

Versions are at most 64 characters from `A-Z a-z 0-9 . - + _ ~`. The object is always written in
this field order, with no spaces; rollcall's own reader (`internal/attest` `Decode`) takes only
that form.

## What is signed

The signature is Ed25519, with the member's own signing key (the key its history entries are
signed with, the one the roster names for it), over these bytes; every integer is big endian:

| Bytes | Field |
|---|---|
| 19 | `rollcall/v1/attest` and one zero byte |
| 8 | length of the nonce |
| 16 to 64 | the nonce |
| 16 | member ID |
| 8 | head seq |
| 32 | head hash |
| 16 | kernel boot ID |
| 16 | boot ID of the newest boot record |
| 8 | its boot seq |
| 8 | length of the OpenWrt release |
| n | the OpenWrt release, its ASCII bytes |
| 8 | length of the rollcall version |
| n | the rollcall version, its ASCII bytes |
| 8 | time, Unix seconds, two's complement |

Every variable field carries its length, so the bytes have one reading. The first 19 bytes are
the signature's domain: rollcall signs a history entry over `rollcall/v1/entry` and a zero byte,
a roster over `rollcall/v1/roster` and a zero byte, and so on for each kind it signs. No kind
holds a zero byte, so a signature made for one kind never verifies as another, whatever bytes
follow: an attest signature never passes as a history entry or a roster, and theirs never as an
attest (`TestAttestDomainSeparated`).

## Verifying it

1. Generate a fresh random nonce of 16 to 64 bytes; never send one twice.
2. Run `rollcall attest --nonce <hex>` on the router, then read the history file in the same
   session. In that order, the chain read holds the signed head (the router may add entries in
   between, never remove them).
3. Parse the JSON. Check that `nonce` is yours.
4. Build the bytes above from the fields and verify `sig` with Ed25519 under the member key you
   pinned for the router (from its roster entry, never from the router's word at the time of the
   check). Refuse a public key of small order, as rollcall does.
5. Compare with what you read: `member` is the pinned member; the chain read holds an entry at
   `head.seq` whose hash is `head.hash`; the newest boot record at or before it names `boot.id`,
   `boot.seq` and `boot.openwrt`.
6. Compare `kernel_boot_id` with `boot.id`. Equal: the router that answers is running the boot
   its chain records last. Different: it answers from a boot it has not recorded (a daemon that
   has not started since the boot, or the files running somewhere else).
7. Judge `time` against your own clock with the slack you allow; a router without NTP since a
   power cut has a wrong clock (design 3).

What it binds: the answer cannot be made before the nonce exists, so a copy of old answers fails;
and a copy of the files run elsewhere answers with that machine's kernel boot ID, not the one the
chain records, and any boot record it adds forks the chain away from the router's. The member key
is a file on the router; whoever holds a copy of `/etc/rollcall` holds the key too. A key held in
hardware, which no copy carries, is a separate tier.

## Test vector

The member key's seed is the 32 bytes `00 01 02 .. 1f`. The statement is the JSON of
[The output](#the-output).

- Public key: `03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8`
- Signed bytes (179):

```
726f6c6c63616c6c2f76312f61747465737400              rollcall/v1/attest, 0
0000000000000010                                    nonce length 16
f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff                    nonce
00112233445566778899aabbccddeeff                    member
000000000000002a                                    head seq 42
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                                                    head hash
4e7c1b2a9d3f40e8b5a6c7d8e9f00112                    kernel boot ID
4e7c1b2a9d3f40e8b5a6c7d8e9f00112                    boot ID of the newest boot record
0000000000000007                                    its boot seq 7
0000000000000007 32352e31322e34                     OpenWrt "25.12.4"
0000000000000009 312e302e302d726332                 rollcall "1.0.0-rc2"
000000006af06440                                    time 1794139200 = 2026-11-08T12:00:00Z
```

- Signature: `384f30a0c33980c035f299d008cca53cbc591298f7564c39d425530b68c48f43da7de68154f01e0f41f8f0ec0bae68d49330385a570d6ba157f3c0a1899dfe05`

A second vector, with the same key: a router answering from a boot its chain has not recorded,
with the longest nonce. Every field differs from its neighbours, so a verifier that swaps two
fields or reads one at the wrong width fails it.

```
726f6c6c63616c6c2f76312f61747465737400              rollcall/v1/attest, 0
0000000000000040                                    nonce length 64
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
                                                    nonce 00 .. 3f
ffeeddccbbaa99887766554433221100                    member
00000000000f4240                                    head seq 1000000
0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
                                                    head hash 01 .. 20
11111111222222223333333344444444                    kernel boot ID
99999999888888887777777766666666                    boot ID of the newest boot record
000000000000012c                                    its boot seq 300
0000000000000007 32342e31302e35                     OpenWrt "24.10.5"
0000000000000005 312e302e30                         rollcall "1.0.0"
000000006af0795d                                    time 1794144605 = 2026-11-08T13:30:05Z
```

- Signature: `6618344b394fc28c0d8e81af3a770a23aa64ba8a240a24eb9e982a076ef497c881866484cd6237efbafa74c80a8338fe95761249bbdea839bc0e7f6a443c900e`

Both signatures were computed with Go's `crypto/ed25519` over those bytes written out by hand,
with no rollcall code; `TestAttestVector` and `TestAttestVectorUnrecorded` in `internal/attest`
hold rollcall to the same bytes and signatures, and the first to the same JSON.
