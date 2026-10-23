package main

import (
	"slices"
	"testing"
)

func TestReadProfile(t *testing.T) {
	good := `{"defaultAction": "SCMP_ACT_KILL_PROCESS", "syscalls": [{"names": ["read", "write"], "action": "SCMP_ACT_ALLOW"}]}`
	names, err := readProfile([]byte(good))
	if err != nil || !slices.Equal(names, []string{"read", "write"}) {
		t.Fatalf("readProfile(good) = %v, %v", names, err)
	}
	bad := map[string]string{
		"default allows":   `{"defaultAction": "SCMP_ACT_ALLOW", "syscalls": [{"names": ["read"], "action": "SCMP_ACT_ALLOW"}]}`,
		"default errno":    `{"defaultAction": "SCMP_ACT_ERRNO", "syscalls": [{"names": ["read"], "action": "SCMP_ACT_ALLOW"}]}`,
		"rule not allow":   `{"defaultAction": "SCMP_ACT_KILL_PROCESS", "syscalls": [{"names": ["read"], "action": "SCMP_ACT_LOG"}]}`,
		"no names":         `{"defaultAction": "SCMP_ACT_KILL_PROCESS", "syscalls": [{"names": [], "action": "SCMP_ACT_ALLOW"}]}`,
		"no rules":         `{"defaultAction": "SCMP_ACT_KILL_PROCESS", "syscalls": []}`,
		"unknown field":    `{"defaultAction": "SCMP_ACT_KILL_PROCESS", "args": 1, "syscalls": [{"names": ["read"], "action": "SCMP_ACT_ALLOW"}]}`,
		"not json":         `{"defaultAction" "SCMP_ACT_KILL_PROCESS"}`,
		"trailing garbage": good + `{}`,
	}
	for name, text := range bad {
		if _, err := readProfile([]byte(text)); err == nil {
			t.Errorf("%s: readProfile accepted %s", name, text)
		}
	}
}
