Feature: A router's own link changes reach the chat as few messages
  Each router watches its own uplink: its WAN interface, the internet behind it, and the DNS
  servers the uplink names. What one router's links do within half a minute is one message:
  the start of an outage in one line, its end in one line, and a link that keeps dropping in
  one line that counts the drops.

  # @decided 2026-10-30: the link changes of one router (WAN, internet, DNS, lost or back) that
  # follow each other within 30 s go out as one message: the losses that open an outage in one
  # line, the returns that close it in one line, and a link that drops and returns again and
  # again as one incident with the number of drops and the time it was down. The first alert of
  # an outage comes about 30 s later in exchange. Silences, reboots and roster changes keep the
  # 10 s window.
  # @decided 2026-10-30, on the measured price: for two messages an outage, the first alert of a
  # WAN cut comes about 40 to 45 s later than before, of an internet loss alone about 20 s later,
  # since the internet probe records its loss about 20 s after the WAN went down.
  # @measured 2026-10-30, lab cell R1.4 on rc92 (e3f542e): beryl2's WAN flapped ten times, 5 s
  # down and 5 s up; the chat got 6 messages in 2 minutes.
  @test:TestFlappingWanToldAsOneOutage
  Scenario: A router's WAN keeps dropping for two minutes
    Given a router whose WAN goes down and comes back again and again for two minutes
    And its internet probe finds the internet gone and back meanwhile
    When the WAN stays up at last
    Then the chat gets at most two messages about it
    And the last one tells how many times the WAN went down and for how long in all

  # A review of the 30 s window, 2026-10-30: a WAN that never stops dropping, 5 s down and 5 s up
  # for 10 minutes, gave one message at its end only, 10 minutes after it began.
  @test:TestEndlessFlapToldWhileItFlaps
  Scenario: A router's WAN never stops dropping
    Given a router whose WAN goes down for 5 seconds and up for 5 seconds, again and again
    And its internet probe finds the internet gone meanwhile
    Then the chat is told within 90 seconds of the first drop, while the WAN still flaps
    And that message says the WAN keeps dropping, not that it was down
    When the WAN stays up at last, ten minutes later, and the internet is back
    Then the chat gets one more message: the whole outage, with every drop counted

  @test:TestShortFlapCutByTheCeilingIsEnded
  Scenario: A flap told while it lasts ends soon after
    Given a router's WAN drops four times in half a minute and stays up
    And the chat was told it keeps dropping before its chain was quiet
    Then the chat also gets its end, with the drops counted

  @test:TestEndAfterAFlappingStartIsTold
  Scenario: The end of an outage whose start flapped
    Given a router's WAN drops, comes back for a few seconds, drops again and stays down
    And the chat was told the start with its two drops
    When the WAN comes back minutes later
    Then the chat gets the end of the outage with its length and both drops

  @test:TestFlapEndsTheOpenLoss
  Scenario: A WAN told as down drops a few more times and stays up
    Given a router's WAN went down and the chat was told
    When the WAN comes back, drops twice more, and stays up
    Then the chat gets one more message, the outage from the first loss with its drops
    And a later drop of that WAN is told with its own length

  # @measured 2026-10-30, lab cell O1 on rc92: beryl2's uplink was down for 2 h; the chat got 4
  # messages, "WAN went down" and "internet lost" at the start, and two ends, because the WAN
  # and the internet came back 11 s apart, outside the 10 s window.
  @test:TestTwoHourUplinkLossTwoMessages
  Scenario: A router's WAN and internet are down for two hours
    Given a router loses its WAN, and its internet probe finds the internet gone 20 seconds later
    When both come back two hours later, 11 seconds apart
    Then the chat gets one message when the outage begins, naming the WAN and the internet
    And one message when it ends, with its length

  # @measured 2026-10-30, lab cell R1.5 on rc92: both uplinks were down for 2 minutes; the chat
  # got 3 messages, the start in two and the end in one.
  @test:TestBothUplinksDownTwoMessages
  Scenario: Two routers lose their uplinks together
    Given two routers lose their WAN and then their internet at the same moment
    When both come back two minutes later
    Then the chat gets two messages, the start and the end, each naming both routers

  # @measured 2026-10-30, lab cells D3 and D4 on rc92: the internet behind one router was cut
  # for 5 minutes; the chat got the loss and the outage with its length, 2 messages.
  @test:TestInternetOnlyLossTwoMessages
  Scenario: Only the internet is lost
    Given a router keeps its WAN and loses the internet behind it for five minutes
    Then the chat gets the start of the outage and its end, two messages as before

  # @measured 2026-10-30, lab cells D1 and D2 on rc92: the uplink dropped DNS (TCP and UDP 53
  # and 853) for 5 minutes while TCP to 1.1.1.1 and 8.8.8.8 worked; the router's resolver did
  # not resolve gnu.org or python.org, and rollcall reported nothing.
  @test:TestDNSCutToldAsItsOwnIncident
  Scenario: The uplink's DNS servers stop answering while the internet works
    Given a router whose uplink DNS servers stop answering for five minutes
    And its internet probe still reaches the internet
    Then the chat is told that DNS stopped answering
    When DNS answers again
    Then the chat gets one message with the length of the cut
    And neither message says the internet was lost

  @test:TestHostTellsDNSCut
  Scenario: The router finds a DNS cut on its own
    Given the router's internet probe reaches the internet
    And the DNS servers its uplink names stop answering
    When three rounds of the DNS probe fail in a row
    Then the router records that DNS was lost, dated at the first failed round
    When one round gets an answer again
    Then the router records that DNS is back

  @test:TestHostNoDNSLossWithoutInternet
  Scenario: DNS fails because the whole internet is gone
    Given a router loses its internet, and with it every DNS answer
    Then the router records that the internet was lost
    And it records nothing about DNS

  @test:TestDNSProbeAnswerCounts
  Scenario: Any answer from the uplink's DNS servers counts as DNS working
    Given the DNS servers the uplink names
    When one of them answers, even that the name does not exist
    Then the round counts as DNS working
    When every one of them fails, refuses or does not answer in time
    Then the round counts as DNS failing

  @test:TestDNSProbeOffWithoutServers
  Scenario: Without DNS servers on the uplink the DNS probe judges nothing
    Given the uplink names no DNS server and the configuration names none
    Then a round of the DNS probe counts neither way
    And the router's log says so once, not once per round

  @test:TestLateLossJoinsTheStart
  Scenario: A loss found late joins the start of its outage
    Given a router's WAN went down
    And its internet probe dates the internet loss within 30 seconds of it, but records it later
    Then the chat gets one message for the start of the outage
    And the end of the outage tells both links

  @test:TestSilenceReportedSoon
  Scenario: A silence keeps the 10 second window
    Given a router loses power
    Then the chat tells its silence within 45 seconds of the cut

  @test:TestOlderMemberDNSIncidentsAcknowledged
  Scenario: A router of an older version does not know DNS events
    Given a group where a router of an older version holds DNS events as facts of their own
    When a newer router tells the DNS cut and its end
    Then every incident the older router made of them counts as told
    And none is left for it to send later

  @test:TestOlderSenderToldTheOutageInPieces
  Scenario: The sender is a router of an older version
    Given a group whose sender runs an older version, with the 10 second window
    When a newer router's WAN keeps dropping and the sender tells it in six messages
    Then the newer routers count their own incident of it told
    And they keep nothing of it to send when they take over sending

  # Lab night of 2026-10-30 on rc93: a router upgraded from rc92 had kept a WAN flap of the day in
  # pieces, a return and the drop after it, while the return that ended the flap lay in another
  # piece; ten hours later the end of a 2 min outage was told as "WAN was down from 12:06 to 22:09
  # (10 h 3 min)".
  @test:TestOlderPiecesOfAFlapDoNotStretchALaterOutage @test:TestOpenLinksTakeLaterReturns
  Scenario: An outage after an upgrade is told with its own length
    Given a router kept an earlier flap of its WAN in pieces, each a return and the drop after it
    And the return that ended the flap is kept in another piece
    When its WAN and internet go down an hour later and come back after 2 min 26 s
    Then the chat gets two messages, the start and the end of that outage
    And the end tells 2 min 26 s, not an outage reaching back to the flap

  # Lab cell V-R1.5-rc94, 2026-10-31: both uplinks down; the internet probes recorded their losses
  # 20 and 30 s after the cut, so the 60 s ceiling made the start, and the chain went quiet 3 s later
  # with both links still down: the start went out twice, 3 s apart.
  @test:TestLateLossesPastTheCeilingOneStart
  Scenario: Losses recorded late do not tell the start twice
    Given two routers lose their WAN at once
    And their internet probes record the losses 20 and 30 seconds after the cut
    When both links come back after two and a half minutes
    Then the chat gets two messages, the start and the end of the outage

  # A replay of the forge night campaign, 2026-10-31, not seen on a router: a WAN that kept dropping
  # for 90 s and then stayed down had its flapping and its down state told, and its return never.
  @test:TestEndOfAFlapThatStayedDownIsTold
  Scenario: The return after a flap that stayed down is told
    Given a router's WAN goes down and up every 5 seconds for 90 or 110 seconds
    And then it stays down
    When its WAN comes back at 5 minutes after the first drop
    Then the chat is told the WAN keeps dropping, then that it is down with its drops
    And then that it was down for 5 minutes, with every drop counted
