# rollcall v1 delivery report

Scaffold. Counts that need a full test run are TBD and are filled in at delivery. The invariants are listed in CLAUDE.md.

```text
Tier:       T3, because v1 carries the cryptography, the roster authority and the tamper-evident history, where a wrong answer is silent
Scenarios:  features/*.feature, 10, every one bound to a test
            features/group.feature carries "# bindings-pending", so TestFeatureBindings excuses it; its 10 tags were checked by hand against the test functions in internal/sim/scenarios_test.go
            A router loses power and comes back: Given a group of routers on one site, When one router loses power, Then another reports it silent within 30 seconds -> TestPowerLossReported
            The router that talks to Telegram loses its internet connection: Given that router has no internet connection, When the sending router stays silent past the takeover window, Then the other router takes over sending and reports the lost connection -> TestSenderLosesInternetOtherTakesOver
            No router can reach Telegram for twenty minutes: Given no router in the group can reach Telegram for twenty minutes, When Telegram becomes reachable again, Then one message reports the outage with its start, end and duration -> TestNobodyReachesTelegram20Min
            A planned reboot is reported differently from a crash: Given one router is rebooted on purpose and another crashes, When the group reports both, Then the planned reboot is reported as planned and the crash as a crash -> TestPlannedVsCrash
            A firmware upgrade is reported with the old and the new version: Given a router is upgraded, When it comes back after the upgrade, Then the group reports the upgrade with the old and the new version -> TestUpgradeReported
            A day without incidents leaves the chat empty: Given the group runs for a whole day without any incident, Then the Telegram chat receives no message that day -> TestQuietDayEmptyChat
            A mesh node loses its radio link but stays up: Given a mesh node that stays powered, When it loses its radio link to the rest of the mesh, Then the group reports a link problem and does not report a reboot -> TestMeshNodeLinkLoss
            Separate routers, each with its own LAN and DHCP server, form one group: Given two such routers, When they are joined into one group, Then each sees the other as a member -> TestSeparateRoutersFormGroup
            A single router works on its own: Given a group that holds only one router, When that router has an incident, Then the group still reports the incident -> TestSingleRouterGroup
            A device on the LAN that was never paired cannot inject events: Given such a device, When it sends an event to the group, Then the group ignores it and no message reaches Telegram for it -> TestUnpairedDeviceCannotInject
Red first:  TBD. This scaffold adds no test; each task records its own red run (command and failing lines)
Tests:      TBD new, TBD total, all green (full go test ./... runs at delivery)
Gate:       8 gates in internal/gates, each with teeth cases; scripts/gates-have-teeth.sh runs them; this scaffold adds no gate
            internal/gates/imports_test.go TestDaemonDoesNotImportExec: the daemon build graph (go list -deps, linux/arm64) has no os/exec; teeth: yes, 3 cases
            internal/gates/deps_test.go TestDependencyAllowlist: go.mod requires only golang.org/x/crypto and golang.org/x/sys, and replaces only with local directories; teeth: yes, 6 cases
            internal/gates/tls_test.go TestNoInsecureSkipVerify: InsecureSkipVerify, VerifyPeerCertificate and VerifyConnection appear in no non-test Go file; teeth: yes, 5 cases
            internal/gates/features_test.go TestFeatureBindings: every scenario carries an @test tag that names an existing test, and every tag names one; teeth: yes, 7 cases; group.feature is excused by its pending marker for now
            internal/gates/initscript_test.go TestInitScriptHardening: the service file sets user, group, no_new_privs, seccomp and a requirejail jail, and never uses ubus; teeth: yes, 7 cases
            internal/gates/luci_test.go TestLuCINoInnerHTML: no DOM markup sink in luci-app-rollcall JavaScript, and every E() child is an array, an E() or a T(); teeth: yes, 9 cases
            internal/gates/seccomp_test.go TestSeccompProfilesPerArch: every shipped profile parses, kills by default, carries arch_prctl only on amd64 and no legacy name on aarch64; teeth: yes, 7 cases
            internal/gates/coverage_test.go TestCoverageNotBelowBaseline: total statement coverage is not below coverage-baseline.txt (runs with ROLLCALL_COVERAGE=1); teeth: yes, 3 cases; the baseline file holds 0.0
            Not gates: internal/gates/teeth_test.go (TestGatesHaveTeeth, the harness), internal/gates/repo_test.go (helpers), scripts/mkipk.sh and scripts/mkapk.sh (packaging). CI also runs go mod verify, govulncheck and the 200-seed sweep (TestSweep); none of them is a repo gate
Metrics:    fmt/vet/lint clean: TBD; coverage TBD (baseline 0.0); uncovered that matters: TBD
Ran it:     TBD. This scaffold ran no tests; the scenario tags and the gate sources were read and searched, not executed
NOT proven: the router lab run (Task 27) has not happened, so the group has not run on real routers
            real Telegram delivery has not been exercised; the channel tests use local fake servers only
            v1.1 checkpoints signed by a majority are out of scope; the kind is reserved and no quorum logic exists
            sandbox and seccomp behaviour on OpenWrt 24.10 and 25.12 hardware is not shown
            the 10 scenarios, the gates and the sweep have not run in this scaffold; mutation testing (T3) has not run
```
