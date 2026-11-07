Feature: A new version of the package takes over on the router
  An upgrade from the feed replaces the files of a running router, and apk then runs post-upgrade,
  not post-install; opkg runs its postinst with PKG_UPGRADE=1. @decided 2026-11-07: an upgrade does
  what it must for the new version to run and leaves the owner's choice alone: it restarts a service
  that is enabled and never enables one.

  @test:TestPackageUpgradeScripts
  Scenario: An upgrade puts an enabled service on the new binary
    Given rollcall is installed and enabled on a router
    When the package is replaced by a newer version
    Then the service restarts, so the new daemon runs and not the old one
    And that start brings the firewall rules in line and writes the snapshot

  @test:TestPackageUpgradeScripts
  Scenario: An upgrade leaves a service the owner switched off as it is
    Given the owner has disabled rollcall
    When the package is replaced by a newer version
    Then the service is not started and is not enabled
    And its firewall rules are brought in line all the same

  @test:TestPackageUpgradeScripts
  Scenario: An upgrade makes sure of the account and the state directory
    Given a router that lost the rollcall account, or whose /etc/rollcall was changed
    When the package is replaced by a newer version
    Then the account exists and the directory is rollcall's, 0700, before the service starts

  @test:TestPackageUpgradeScripts
  Scenario: A restart that fails does not break the package
    Given the service cannot start after an upgrade
    When the package is replaced by a newer version
    Then the upgrade itself still succeeds

  @test:TestPackageUpgradeScripts
  Scenario: An install still leaves the daemon stopped
    When the package is installed for the first time
    Then the account, the state directory and the firewall rules are made and the service is enabled
    And the daemon does not start, because it needs rollcall init first

  @test:TestPackageUpgradeScripts
  Scenario: Both package formats do the same
    Given the postinst that opkg runs, and the post-upgrade that apk runs
    When each runs for an upgrade
    Then each restarts only an enabled service and neither enables one

  @test:TestPackageUpgradeScripts
  Scenario: A new LuCI page shows after an upgrade
    When luci-app-rollcall is replaced by a newer version
    Then the caches of the LuCI menu are cleared, as they are on an install
