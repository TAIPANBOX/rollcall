Feature: The daemon runs only inside its system call filter
  On a router rollcalld runs only sandboxed. procd cannot put a seccomp filter on a statically
  linked program, so the daemon installs its own at start, from the list the package ships for
  its architecture, before it opens any file or socket, and does not run when it cannot.

  @test:TestFilterKillsForbiddenCall
  Scenario: A system call outside the list ends the daemon
    Given rollcalld has installed its seccomp filter
    When it makes a system call its architecture's list does not hold
    Then the kernel ends the whole process with SIGSYS

  @test:TestFilterCoversEveryThread
  Scenario: Every thread of the daemon is filtered
    Given a thread of the daemon that was running before the filter went on
    When that thread makes a system call outside the list
    Then the kernel ends the whole process with SIGSYS

  @test:TestSeccompDaemonListIsTheProfile
  Scenario: The filter is the list the package ships
    Given the profile the package installs as /etc/seccomp/rollcall.json for an architecture
    When rollcalld for that architecture builds its filter
    Then the filter allows exactly the system calls the profile lists

  @test:TestDaemonConfinesFirst
  Scenario: Nothing is opened before the filter is in force
    Given rollcalld is starting
    When it has read its command line
    Then it installs its filter before it opens any file or socket
    And it stops with the reason when the filter cannot be installed

  @test:TestSandboxGate
  Scenario: The daemon does not listen without its sandbox
    Given the kernel does not report no_new_privs and a seccomp filter in force for the daemon
    When the daemon is about to listen
    Then it refuses and says why
