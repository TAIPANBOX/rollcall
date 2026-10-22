# bindings-pending
Feature: Router group watches itself and reports incidents
  Routers on one site watch each other and report what happened through
  whichever of them can still reach Telegram.

  @test:TestPowerLossReported
  Scenario: A router loses power and comes back
    Given a group of routers on one site
    When one router loses power
    Then another router reports it silent within 30 seconds
    When the router comes back
    Then the group reports an unexpected reboot with the downtime

  @test:TestSenderLosesInternetOtherTakesOver
  Scenario: The router that talks to Telegram loses its internet connection
    Given the router that talks to Telegram has no internet connection
    And another router in the group has its own internet connection
    When the sending router stays silent past the takeover window
    Then the other router takes over sending
    And it reports the lost connection

  @test:TestNobodyReachesTelegram20Min
  Scenario: No router can reach Telegram for twenty minutes
    Given no router in the group can reach Telegram for twenty minutes
    When Telegram becomes reachable again
    Then one message reports the outage with its start, its end and its duration
    And no incident seen during the outage is lost

  @test:TestPlannedVsCrash
  Scenario: A planned reboot is reported differently from a crash
    Given one router is rebooted on purpose
    And another router crashes without warning
    When the group reports both
    Then the planned reboot is reported as planned
    And the crash is reported as a crash

  @test:TestUpgradeReported
  Scenario: A firmware upgrade is reported with the old and the new version
    Given a router in the group is upgraded to a new version
    When it comes back after the upgrade
    Then the group reports the upgrade with the old and the new version

  @test:TestQuietDayEmptyChat
  Scenario: A day without incidents leaves the chat empty
    Given the group runs for a whole day without any incident
    Then the Telegram chat receives no message that day

  @test:TestMeshNodeLinkLoss
  Scenario: A mesh node loses its radio link but stays up
    Given a mesh node that stays powered and keeps running
    When it loses its radio link to the rest of the mesh
    Then the group reports a link problem
    And it does not report a reboot

  @test:TestSeparateRoutersFormGroup
  Scenario: Separate routers, each with its own LAN and DHCP server, form one group
    Given two routers that each serve their own LAN with their own DHCP
    When they are joined into one group
    Then each router sees the other as a member of the group

  @test:TestSingleRouterGroup
  Scenario: A single router works on its own
    Given a group that holds only one router
    When that router has an incident
    Then the group still reports the incident

  @test:TestUnpairedDeviceCannotInject
  Scenario: A device on the LAN that was never paired cannot inject events
    Given a device on the LAN that was never paired with the group
    When it sends an event to the group
    Then the group ignores the event
    And no message reaches Telegram for it
