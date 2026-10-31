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

  # @measured 2026-10-30 on a lab router: every rollcalld line, routine ones included, was
  # logged as daemon.err, and nothing in the log said which incidents had reached the chat.
  @test:TestChatSendsAreLogged
  Scenario: Every message to the chat leaves one line in the router's log
    Given the sending router tells the chat about incidents
    When a message reaches the chat
    Then the router's log holds one line with that message's tag
    When Telegram cannot be reached for a while
    Then the log says so once, not once per attempt

  @test:TestSetLogs
  Scenario: Routine lines and problems are logged at different levels
    Given rollcalld runs under procd
    When it logs a routine line, such as the control command the ntp hook runs every 11 minutes
    Then the line is logged as information
    When it logs a problem
    Then the line is logged as an error

  # @measured 2026-10-29 on lab routers: two routers lost their WAN 88 s apart and got it back
  # 2 s apart; the first router's loss stayed open, and its next WAN blip 11 h later was told as
  # an outage of 11 h 29 min.
  @test:TestOverlappingWanLossesBothClose
  Scenario: Two routers lose their WAN at different moments and get it back together
    Given two routers in the group lose their WAN a minute and a half apart
    When both get it back within seconds of each other
    Then the chat tells one outage from the first loss to the last return
    And a later loss of either router is told with its own length

  @test:TestRestoreEndsOnlyItsOwnRoutersLoss
  Scenario: A router's return does not end another router's outage
    Given one router has lost its WAN
    When another router, whose WAN was never down, reports its WAN up
    Then the outage of the first router stays open
    And it ends only when the first router's own WAN comes back

  # @measured 2026-10-30 on a lab router: its uplink port was down for 3 minutes; the return
  # ended the internet outage only, and the WAN loss stayed open.
  @test:TestWanAndInternetBackTogetherBothClose
  Scenario: The WAN and the internet come back together
    Given the sending router has lost its WAN and then its internet
    When its WAN and its internet come back within seconds
    Then both losses end
    And a later loss of its WAN is told with its own length

  # @measured 2026-10-31 by the simulator sweep, ROLLCALL_SEEDS=1000 on 98a14b1: seeds 241 and 698
  # each sent one router's update ("r03 rebooted unexpectedly, back at 09:05.") twice, 1 s apart,
  # from one sender and without a partition. The claims about one absence reached the router in two
  # reconciliations, and each correction recorded an update of its own.
  @test:TestOneUpdatePerAbsence
  Scenario: A router corrects what was said about one absence and the chat hears it once
    Given a router lost power twice while another router last heard it before the first cut
    And that router told the group the first router had gone silent
    When the first router comes back, corrects that claim and the chat gets its update
    And another claim about the same absence reaches it later
    Then it corrects that claim too
    And the chat does not get the update a second time
