package main

import (
	"bytes"
	"log"
	"os"
	"testing"
)

// TestSetLogs: a routine line goes to stdout and a problem to stderr, so procd
// logs the first as daemon.info and the second as daemon.err. On a router on
// 2026-10-30 every rollcalld line, "listening on" and the control audit line
// every 11 minutes included, was daemon.err.
func TestSetLogs(t *testing.T) {
	defer log.SetOutput(os.Stderr)
	defer log.SetFlags(log.Flags())
	var out, errw bytes.Buffer
	problems := setLogs(&out, &errw)
	log.Print("rollcalld: listening")
	problems.Print("rollcalld: the node does not run")
	if out.String() != "rollcalld: listening\n" {
		t.Errorf("stdout %q; want the routine line alone", out.String())
	}
	if errw.String() != "rollcalld: the node does not run\n" {
		t.Errorf("stderr %q; want the problem alone", errw.String())
	}
}
