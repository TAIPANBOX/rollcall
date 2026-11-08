Feature: An auditor outside the router asks it for a fresh signed statement
  An auditor that reads a router's signed history over SSH cannot tell the live router from a frozen
  copy of its files, as nothing it reads answers a question of its own. @decided 2026-11-08: rollcall
  signs, with the router's member key and under a signature domain of its own, a statement of the
  router's state over a nonce the auditor chose, and writes nothing while it does.

  @test:TestAttestCommand
  Scenario: The router answers a fresh nonce with a signed statement of its state
    Given a router whose daemon wrote its own history
    When the auditor runs rollcall attest as root with a fresh nonce
    Then the router prints one JSON statement signed with its member key over that nonce
    And it names its member ID, the head of its own history and the kernel's boot ID now
    And the boot ID, boot counter and OpenWrt release of its latest boot record, its rollcall version and the time

  @test:TestAttestShowsACopy
  Scenario: A copy of the router's files cannot pass for the router
    Given a copy of the router's files taken earlier
    When the auditor asks with a nonce it never used before
    Then an answer kept from before does not verify for that nonce
    And a copy run on another machine names a kernel boot ID other than the one its latest boot record names

  @test:TestAttestDomainSeparated
  Scenario: A statement's signature never passes for a history entry or a roster
    Given the member key that signs the statement also signs the router's history entries
    When a statement and an entry are signed over the same bytes
    Then neither signature verifies as the other kind

  @test:TestAttestVector
  Scenario: The auditor checks a statement without rollcall's code
    Given the byte format and the test vector in docs/attest.md
    When a verifier builds the signed bytes from them alone
    Then plain Ed25519 gives the vector's signature, and rollcall signs and prints the same

  @test:TestAttestFieldsAreSigned
  Scenario: Every field of the statement is under the signature
    When any one field of a statement is changed
    Then the statement no longer verifies

  @test:TestParseNonceHostile
  @test:TestAttestNonceArgv
  Scenario: A nonce that is not 16 to 64 bytes in hex is refused
    Given a nonce that is empty, too short, too long, of odd length or not hex
    When the auditor runs rollcall attest with it
    Then the command refuses it before it reads the key, the history or the boot ID

  @test:TestAttestWritesNothing
  @test:TestReadOwnWritesNothing
  Scenario: An hourly check wears nothing
    When the auditor runs rollcall attest a hundred times
    Then no file of the state directory, nor the directory itself, has changed

  @test:TestAttestNeedsRoot
  @test:TestReadOwnKeyChecks
  Scenario: Only root signs, with the key read as the daemon reads it
    Given a user other than root, or a key or history file open to group or others
    When rollcall attest runs
    Then it refuses and signs nothing

  @test:TestReadOwnRefusesBrokenHistory
  @test:TestReadOwnTakesHeadAndLatestBoot
  Scenario: Only the router's own history, verified whole, is vouched for
    Given an own history file with an entry changed, left out, swapped or of another member
    When rollcall attest runs
    Then it refuses and signs nothing
    And on the chain as the daemon wrote it, it signs the newest entry and the newest boot record
