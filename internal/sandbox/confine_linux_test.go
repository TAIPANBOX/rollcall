//go:build linux && !race && (amd64 || arm64 || arm || mips || mipsle)

// The race detector's runtime makes system calls of its own, which no rollcall list allows, so
// these tests run without it; the CI seccomp job runs them on amd64 and arm64.

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// childEnv names the mode in which TestMain runs this binary as a child instead of the tests.
const childEnv = "ROLLCALL_SANDBOX_CHILD"

func TestMain(m *testing.M) {
	if mode := os.Getenv(childEnv); mode != "" {
		os.Exit(child(mode))
	}
	os.Exit(m.Run())
}

// child runs in the re-executed test binary. It installs the daemon's filter with Confine, as
// rollcalld does at start, and then does what the mode says. getppid is the forbidden call: it
// is in no rollcall list, and nothing in the Go runtime makes it.
func child(mode string) int {
	say := func(format string, a ...any) { fmt.Fprintf(os.Stdout, format+"\n", a...) }
	switch mode {
	case "forbidden":
		if _, err := Confine(); err != nil {
			say("confine: %v", err)
			return 3
		}
		_, _, errno := unix.RawSyscall(unix.SYS_GETPPID, 0, 0, 0)
		say("getppid returned (errno %d): the process was not killed", errno)
		return 0
	case "allowed":
		n, err := Confine()
		if err != nil {
			say("confine: %v", err)
			return 3
		}
		unix.RawSyscall(unix.SYS_GETPID, 0, 0, 0)
		status, err := os.ReadFile("/proc/self/status")
		if err != nil {
			say("read status: %v", err)
			return 3
		}
		say("confined, %d system calls allowed", n)
		os.Stdout.Write(status)
		return 0
	case "thread":
		// The second thread exists before the filter is installed, and it is not the thread
		// that installs it: only TSYNC can put the filter on it.
		ready, goOn, done := make(chan int), make(chan struct{}), make(chan string)
		go func() {
			runtime.LockOSThread()
			ready <- unix.Gettid()
			<-goOn
			_, _, errno := unix.RawSyscall(unix.SYS_GETPPID, 0, 0, 0)
			done <- fmt.Sprintf("errno %d", errno)
		}()
		second := <-ready
		runtime.LockOSThread()
		installer := unix.Gettid()
		if installer == second {
			say("the installer and the second thread are both %d", installer)
			return 4
		}
		say("installer thread %d, second thread %d", installer, second)
		if _, err := Confine(); err != nil {
			say("confine: %v", err)
			return 3
		}
		close(goOn)
		say("the second thread survived getppid (%s): it is not filtered", <-done)
		return 0
	}
	say("unknown mode %q", mode)
	return 5
}

// runChild re-executes this test binary in the mode and returns its output and its end.
func runChild(t *testing.T, mode string) (string, *os.ProcessState) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), childEnv+"="+mode)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("the %s child did not end within 30 s; output:\n%s", mode, out)
	}
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		t.Fatalf("run the %s child: %v", mode, err)
	}
	return string(out), cmd.ProcessState
}

// signalOf is the signal that ended the process, or 0 when it exited.
func signalOf(ps *os.ProcessState) syscall.Signal {
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return ws.Signal()
	}
	return 0
}

// TestFilterKillsForbiddenCall is the filter rollcalld installs at start, in a real process: a
// system call its list does not hold ends the whole process with SIGSYS.
func TestFilterKillsForbiddenCall(t *testing.T) {
	out, ps := runChild(t, "forbidden")
	if sig := signalOf(ps); sig != syscall.SIGSYS {
		t.Fatalf("the child ended with %v; want death by SIGSYS at getppid; output:\n%s", ps, out)
	}
}

// TestFilterAllowsListedCalls is the other half: the same filter lets a listed call through,
// so the death above is that call's, and the kernel shows the filter in force with
// no_new_privs set, which is what sandboxGate in cmd/rollcalld reads.
func TestFilterAllowsListedCalls(t *testing.T) {
	out, ps := runChild(t, "allowed")
	if !ps.Success() {
		t.Fatalf("the child ended with %v; want exit 0 after getpid and a read of its status; output:\n%s", ps, out)
	}
	for _, want := range []string{"NoNewPrivs:\t1\n", "Seccomp:\t2\n", "system calls allowed"} {
		if !strings.Contains(out, want) {
			t.Errorf("the child's output lacks %q; output:\n%s", want, out)
		}
	}
}

// TestFilterCoversEveryThread is TSYNC: a thread that was running before the filter went on,
// and is not the one that installed it, is filtered too, so a forbidden call there ends the
// process. The Go runtime runs several threads before main starts.
func TestFilterCoversEveryThread(t *testing.T) {
	out, ps := runChild(t, "thread")
	if !strings.Contains(out, "installer thread ") {
		t.Fatalf("the child did not run its second thread apart from the installer (%v); output:\n%s", ps, out)
	}
	if sig := signalOf(ps); sig != syscall.SIGSYS {
		t.Fatalf("the child ended with %v; want death by SIGSYS at getppid on the second thread; output:\n%s", ps, out)
	}
}
