# rollcall v1 delivery report

Taken on 2026-10-23 at commit 2f3f314 (branch feat/v1), unless a line names another commit. Every
figure says how it was taken. The invariants are listed in CLAUDE.md, each with the gate or test
that holds it.

```text
Tier:       T3: v1 carries the cryptography, the roster authority, the tamper-evident history and
            the sandbox, where a wrong answer is silent

Scenarios:  features/group.feature 10 and features/sandbox.feature 5, every one bound to a test;
            TestFeatureBindings checks the binding both ways (no scenario without a test, no tag
            that names nothing), with 7 teeth cases
            A router loses power and comes back                      -> TestPowerLossReported
            The sending router loses its internet connection         -> TestSenderLosesInternetOtherTakesOver
            No router can reach Telegram for twenty minutes          -> TestNobodyReachesTelegram20Min
            A planned reboot reads differently from a crash          -> TestPlannedVsCrash
            A firmware upgrade names the old and the new version     -> TestUpgradeReported
            A day without incidents leaves the chat empty            -> TestQuietDayEmptyChat
            A mesh node loses its radio link but stays up            -> TestMeshNodeLinkLoss
            Separate routers with their own LAN and DHCP form a group -> TestSeparateRoutersFormGroup
            A single router works on its own                         -> TestSingleRouterGroup
            A device that was never paired cannot inject events      -> TestUnpairedDeviceCannotInject
            The five sandbox scenarios bind to the tests of internal/sandbox and the daemon gates

Red first:  every test added for a defect was run against the code before the fix and failed there;
            each commit message or its task record names the failing line. Examples from the lab
            fixes: L1 "etc/init.d/rollcall: user nobody; want root" (82 violations on 41 entries),
            L2 "configuration: open .../network: permission denied", L3 "root runs chown on
            /tmp/rollcall, under /tmp", L4 "the child ended with exit status 0; want death by
            SIGSYS at getppid"

Tests:      go test ./... -count=1 -json at 2f3f314's parent b2f9618, 2026-10-23 19:40 BST, Go 1.27.3
            darwin/arm64: 869 top-level tests pass, 0 fail, 4 skip (two gates that need CI's
            environment, the ICMP probe without CAP_NET_RAW, link-local multicast on macOS);
            902 subtests pass. The Linux-only tests run in CI.
            ROLLCALL_STRICT=1 go test ./internal/sim: pass. CI's 200-seed sweep: 200 clean.
            1000 seeds (strict, run twice on the node wave 2 branch): 1000 clean.

Gate:       16 gates under internal/gates, every one with teeth cases in TestGatesHaveTeeth
            (each case plants the fault the gate exists for and requires the gate to fail, or
            requires it to pass on clean input):
            TestInitScriptHardening (28 cases): user, group, no_new_privs, requirejail, ronly,
              no ubus, capabilities file with every set empty unless icmp, the snapshot written
              before the instance, no network/system/firewall in the jail, nothing prepared under
              /tmp, the control directory mode
            TestLuCINoInnerHTML (9), TestSeccompProfilesPerArch (8), TestPackagesOwnedByRoot (7),
            TestFirewallRuleBuilder (7), TestFeatureBindings (7), TestSeccompRuntimeSetPerArch (6),
            TestDependencyAllowlist (6), TestDaemonConfinesFirst (6),
            TestSeccompDaemonListIsTheProfile (5), TestNoInsecureSkipVerify (5),
            TestSeccompNamesExistPerArch (4), TestNtpHotplugTellsTheDaemon (4),
            TestHotplugNeverBlocks (4), TestDaemonDoesNotImportExec (3),
            TestCoverageNotBelowBaseline (3; baseline raised from 0.0 to 90.0 in 2f3f314)
            CI also runs go mod verify, govulncheck, a byte-identical arm64 rebuild, the package
            content and owner checks, and the daemon under its own seccomp filter (below)

Metrics:    gofmt -l: empty; go vet ./...: clean (darwin and GOOS=linux GOARCH=arm64)
            statement coverage: go test -coverprofile over ./internal/... at b2f9618 94.4%
            (go tool cover -func); CI over ./... with -race on 4186091: 90.3% (run 39990682729)
            mutation (gremlins v0.6.0 in CI, run 39990682729 on 4186091, test efficacy):
            replay 100.00%, epoch 94.34%, roster 93.33%, history 90.65%, deliver 90.57%,
            pairing 84.69%, elect 84.62%, sig 80.00%, wire 80.00%, node 75.38%
            the sig, wire and epoch survivors that were read are equivalent mutants (capacity
            hints, constants); node is the package to raise
            uncovered that matters: the daemon's main and the Linux-only listener paths are
            covered in CI only; the node's own-chain rewrite under a flood of events is bounded by
            the witness budget, not by a test of flash bytes on a router

Ran it:     on routers, 2026-10-23 16:26 to 18:21 BST: a Flint 2 and two Beryl AX, OpenWrt
            25.12.5 aarch64_cortex-a53, rc67 (4186091) and earlier lab builds:
            install, init, two joins (join code piped router to router), roles, chat binding with
            one code; on each router the daemon ran as uid 1660 with NoNewPrivs 1, Seccomp 2 on
            every thread, Seccomp_filters 1, 74 system calls, CapEff 0, a jail with a read-only
            root, SO_BINDTODEVICE true
            chat, verbatim: "home: internet was down from 18:07 to 18:10 (3 min), confirmed by 0
            of 2. Seen by flint2. Times are approximate."; "home: beryl2 rebooted unexpectedly at
            18:11, back after 44 s, confirmed by 0 of 2. Times are approximate."; "home: flint2
            rebooted as planned at 18:16, back after 45 s, confirmed by 1 of 2." One message per
            incident in each case. The count and the "approximate" note were changed afterwards
            (see below).
            in CI on every push: the real rollcalld for x86_64, aarch64 and arm runs 30 s under its
            own filter with no external loader, serves status, binds 7432, forms a group, routes a
            heartbeat to a static peer and has the discovery group socket bound on eth0; the same
            daemon built without prctl, eventfd2 or epoll_pwait in its list dies by SIGSYS

Found by the lab run, fixed:
            L1 every package file was owned by nobody (apk mkpkg named the CI runner's uid as
               nobody), init script and CLI included: fixed in 619a182, gate TestPackagesOwnedByRoot
            L2 network and system configs are root-only on 25.12: the daemon reads a root-written
               snapshot instead, a29ab4d
            L3 root chowned a directory under /tmp: moved to /var/run, b162d61
            L4 procd applies seccomp through LD_PRELOAD, which a static binary ignores: the daemon
               installs its own filter, 594ff50
            L5 full capability bounding set: an empty capabilities file, 11beadd
            L6 a daemon restarted after the clock synced never heard of it: ntp periodic, 96bb936
            L8 "confirmed by 0 of 2" on a reboot both other routers saw: the count now takes the
               routers that recorded the absence, and a router's own internet or WAN loss carries
               no count, 9d2c866
            announcements held while no chat was bound went out out of order, and "roles changed"
            did not say which role: ce0ad9e, 8146a83
            L9 (virtual lab, 2026-10-24) a restart kept the firewall rules of the old peer_zone, so
               the joins were refused: every start now brings the rules in line, gate
               TestInitScriptHardening, test TestFirewallFollowsTheConfiguration

NOT proven: flash wear over days: the long run of 1.0.0-rc1 started on 2026-10-23 at 20:45 on the
            three routers; its figures are not in yet (L5, L6, L8, the role wording and the order
            of announcements ran on the routers that evening: docs/measured.md)
            MIPS has not run anywhere; OpenWrt 24.10 not on a router
            a mesh and NAT: simulator only; separate networks with their own DHCP and static peers:
            virtual x86_64 routers on 2026-10-24 (docs/measured.md), not hardware
            sysupgrade and a pulled power cord: not run (a forced reboot stood in for the cord)
            the LuCI pages on a router: installed, not used
            the hostile-LAN replay and flood checks were not run on the routers; replay and flood
            are covered by unit tests, the simulator and the transport limiter tests
            no release and no signed package feed
            v1.1 checkpoints signed by a majority are out of scope; the kind is reserved only
```
