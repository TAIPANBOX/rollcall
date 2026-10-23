# rollcall

The binding specs are in docs/superpowers/specs.

## Invariants

Each bullet is an invariant from section 12 of the security spec. The marker says what holds it: a gate, a test, or nothing yet.

- I1. Listeners bind only to addresses on the configured peer-zone interfaces and the discovery group. (test: TestListensOnlyOnGivenIfaces in internal/transport/transport_linux_test.go)
- I2. A packet that fails authentication is not processed further, gets no reply and causes no outgoing send. (test: TestUnauthenticatedProducesNothing in internal/node/node_test.go)
- I3. A replayed packet is rejected. (test: TestReplayRejectsDuplicate in internal/replay/replay_test.go)
- I4. A history entry whose signature is not its author's is refused and never changes that author's chain. (test: TestRejectsForeignSignature in internal/history/log_test.go)
- I5a. The roster moves forward one version at a time, and each version carries the hash of the previous one. (test: TestVerifyChain in internal/roster/roster_test.go)
- I5b. A roster version is accepted only with a signature from an admin key or the recovery key. (test: TestVerifyAuthority in internal/roster/roster_test.go)
- I6. Secrets do not appear in the error output of the Telegram and ntfy clients; status and pairing errors have canary tests of their own, while logs and LuCI responses are not searched. (test: TestCanaryNeverInTelegramErrors in internal/channel/telegram_test.go)
- I7. The daemon never imports os/exec. (gate: internal/gates/imports_test.go)
- I8. go.mod requires only the allowed modules and replaces only with local directories. (gate: internal/gates/deps_test.go)
- I9. TLS certificate verification is never disabled or replaced in non-test Go code. (gate: internal/gates/tls_test.go)
- I10. Telegram sendMessage carries no parse_mode and disables link previews. (test: TestTelegramSendHasNoParseMode in internal/channel/telegram_test.go)
- I11. Only a router with the sender role receives the bot token. (test: TestSecretsOnlyForSender in internal/pairing/join_test.go)
- I12. A router with missing or corrupt keys stops and makes no network calls. (test: TestFailClosedWithoutKeys in internal/node/node_test.go)
- I13. The init script sets user, group, no_new_privs, the seccomp profile and a requirejail jail, and never uses ubus. (gate: internal/gates/initscript_test.go)
- I14. A roster has exactly one primary, at most MaxAdmins admins and exactly one recovery key; any other shape is rejected. (test: TestRosterShape in internal/roster/roster_test.go)
- I15a. A takeover is accepted only after ten minutes without hearing the primary, and a primary that returns restores itself. (test: TestTakeoverNeedsTenMinutesOfSilence in internal/node/node_test.go)
- I15b. A takeover that the owner confirmed holds: the replaced primary cannot restore itself. (test: TestConfirmedTakeoverStays in internal/roster/admin_test.go)
- I16. Each roster change produces exactly one chat announcement. (test: TestRosterChangeAnnouncedOnce in internal/node/node_test.go)
- I17a. An entry whose previous hash does not match the chain head is rejected. (test: TestRejectsBrokenPrev in internal/history/log_test.go)
- I17b. Two different signed entries with the same origin and sequence number raise the fork alarm. (test: TestForkDetected in internal/history/log_test.go)
- I18. The history store is append-only: corrections are new entries and never modify existing ones. (test: TestAppendOnly in internal/history/log_test.go)
- I19. A checkpoint is final only with signatures from more than half the roster, and an honest member never signs two different checkpoints at one height. @decided 2026-10-22: checkpoints are scoped to v1.1, and v1 only reserves their kind. (not enforced)
