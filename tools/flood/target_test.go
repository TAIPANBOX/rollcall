package main

import "testing"

func TestCheckTargetAcceptsLANAddresses(t *testing.T) {
	for _, s := range []string{
		"192.168.1.1:7432",
		"10.0.0.5:7432",
		"172.16.0.1:7432",
		"172.31.255.254:7432",
		"127.0.0.1:7432",
		"169.254.20.1:7432",
		"[fe80::1%en8]:7432",
		"[::1]:7432",
		"[fd00::1]:7432",
		"[::ffff:192.168.1.1]:7432",
	} {
		if _, err := checkTarget(s); err != nil {
			t.Errorf("checkTarget(%q): %v, want accepted", s, err)
		}
	}
}

func TestCheckTargetRefusesEverythingElse(t *testing.T) {
	for _, s := range []string{
		"8.8.8.8:7432",
		"1.1.1.1:7432",
		"172.15.255.255:7432",
		"172.32.0.1:7432",
		"192.169.0.1:7432",
		"100.64.0.1:7432", // shared address space, where the tailnet lives
		"0.0.0.0:7432",
		"224.0.0.1:7432",
		"255.255.255.255:7432",
		"[2001:db8::1]:7432",
		"[2606:4700::1111]:7432",
		"[ff02::114]:7432", // the discovery group is multicast, never a flood target
		"[::ffff:8.8.8.8]:7432",
		"example.com:7432",
		"192.168.1.1",
		"192.168.1.1:0",
		"",
	} {
		if _, err := checkTarget(s); err == nil {
			t.Errorf("checkTarget(%q) accepted, want refused", s)
		}
	}
}
