Feature: rollcall's firewall rules stay where they are
  Every start of the service brings the firewall rules that open the rollcall port in line with the
  configuration, and a firewall reload starts the service again. A rule that already holds what the
  configuration needs is left exactly where it is, so a check that compares /etc/config/firewall with
  a baseline sees only changes somebody made. Until 2026-11-12 each start deleted and added the rule
  again, and uci put it at the end of the file, below a section another package had written after it.

  @test:TestFirewallRuleKeepsItsPlace
  Scenario: A firewall reload with nothing changed leaves the file as it was
    Given rollcall's rule rollcall_1, and below it a section another package wrote later
    When the firewall is reloaded and the service starts again
    Then /etc/config/firewall is the same, line for line, and nothing was written to it

  @test:TestFirewallRuleKeepsItsPlace
  Scenario: A changed port or static peer rewrites the rule where it stands
    Given rollcall's rule above a section another package wrote later
    When the port or the static peers change and the service starts again
    Then the rule holds the new values and is still above that section
    And no section that is not rollcall's changed

  @test:TestFirewallRuleKeepsItsPlace
  Scenario: A rule changed by hand is put back in its place
    Given an option added to rollcall's rule by hand, or the section given another type
    When the service starts again
    Then the rule is rollcall's rule again, in the same place

  @test:TestFirewallRuleKeepsItsPlace
  Scenario: A rule no longer needed goes and the others stay
    Given two rules for two peer zones
    When one zone is taken out of the configuration and the service starts again
    Then its rule is removed and the other rule stays where it was
