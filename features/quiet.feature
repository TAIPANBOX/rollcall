Feature: Quiet hours: messages sent at night make no sound
  The owner may set quiet hours in /etc/config/rollcall. A message sent within them reaches the
  chat at once, like any other, with the same text, but the phone neither rings nor vibrates.
  Nothing waits for the morning and nothing is lost: only the sound is off.

  # @decided 2026-10-30: the owner wants to see in the chat what happened at night, without the
  # phone ringing and waking anyone: a message sent within the quiet hours arrives silently and
  # shows at once. The reason, from the lab: one night's test queue would have sent 25 to 35
  # messages to the owner's Telegram.

  @test:TestQuietHoursFollowTheMessagesZone @test:TestQuietHoursReachTelegram
  @test:TestTelegramSilentSendDisablesNotification
  Scenario: A message sent within the quiet hours reaches Telegram without a sound
    Given the quiet hours are 23:00-07:00
    When the sender tells the chat at 23:21 that a router stopped answering
    Then Telegram gets the message with disable_notification set to true
    And the text is the same as at any other hour

  @test:TestTelegramLoudSendUnchanged @test:TestNtfyLoudSendUnchanged
  Scenario: Outside the quiet hours nothing changes
    Given the quiet hours are 23:00-07:00
    When a message is sent at 07:21
    Then Telegram gets byte for byte the request it got before quiet hours existed
    And it carries no disable_notification field
    And ntfy gets no priority header, so the phone rings as before

  @test:TestQuietHoursAcrossMidnight
  Scenario: Quiet hours that run across midnight
    Given the quiet hours are 23:00-07:00
    Then a message sent at 23:30, 00:00, 03:00 or 06:59 makes no sound
    And a message sent at 07:01, 12:00 or 22:59 rings
    And quiet hours of 01:00-05:00 hold 03:00 and not 23:30

  @test:TestQuietHoursEdges
  Scenario: The quiet hours begin at their start and end at their end
    Given the quiet hours are 23:00-07:00
    Then a message sent at 22:59:59 rings
    And a message sent at 23:00:00 sharp makes no sound
    And a message sent at 06:59:59 makes no sound
    And a message sent at 07:00:00 sharp rings

  @test:TestSilentDecidedWhenSent
  Scenario: The moment of sending decides, not the moment of the event
    Given the quiet hours are 23:00-07:00
    And a router went silent at 22:58, while Telegram could not be reached
    When the message goes out at 23:00
    Then it makes no sound
    And a message about 06:59 that goes out at 07:00 rings

  @test:TestQuietHoursFollowTheMessagesZone @test:TestQuietHoursReachTelegram @test:TestQuietHoursLocalTime
  Scenario: The quiet hours are in the time zone the messages show
    Given the router's zone is Europe/Kyiv and the quiet hours are 23:00-07:00
    When a router stops answering at 20:21 UTC, which is 23:21 in Kyiv
    Then the message makes no sound, and it says the router stopped at 23:21
    And a router that stops at 04:21 UTC, 07:21 in Kyiv, is told with a sound

  @test:TestNtfySilentSendIsLowPriority
  Scenario: ntfy gets the low priority, which neither sounds nor vibrates
    Given the quiet hours are 23:00-07:00
    When a message is published to ntfy within them
    Then it carries X-Priority 2, which ntfy delivers with no sound and no vibration
    And its body is the same text

  @test:TestQuietHoursOnlyTheSound
  Scenario: Nothing waits and nothing is lost
    Given the quiet hours hold every moment of the test
    When incidents are queued, a send is rate limited, the bot is blocked and acknowledgements come
    Then every message goes out at the same moment and with the same text as without quiet hours
    And the queue, its retries and its acknowledgements are the same

  @test:TestQuietHoursInvalidRefused @test:TestParseQuietHours
  Scenario: Quiet hours that are not HH:MM-HH:MM are refused
    Given /etc/config/rollcall says option quiet_hours '25:00-07:00'
    When the configuration is loaded
    Then it is refused with the line, the option and the form HH:MM-HH:MM
    And quiet hours that start and end at the same minute are refused too

  @test:TestQuietHoursOffByDefault @test:TestZeroHoursHoldNothing
  Scenario: No quiet hours unless they are set
    Given /etc/config/rollcall has no quiet_hours option, or an empty one
    Then no message is ever sent without a sound
