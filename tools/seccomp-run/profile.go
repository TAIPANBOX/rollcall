package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// profile is the procd seccomp format packaging/seccomp/generate.sh writes.
type profile struct {
	DefaultAction string `json:"defaultAction"`
	Syscalls      []struct {
		Names  []string `json:"names"`
		Action string   `json:"action"`
	} `json:"syscalls"`
}

// readProfile returns the allowed names of a profile, and refuses anything this loader would
// apply differently from the profile's words: a default other than killing the process, a rule
// that is not an allow rule, an empty rule, an unknown field, or anything after the object.
func readProfile(data []byte) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p profile
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("profile: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("profile: data after the object")
	}
	if p.DefaultAction != "SCMP_ACT_KILL_PROCESS" {
		return nil, fmt.Errorf("profile: defaultAction %q; this loader applies only SCMP_ACT_KILL_PROCESS", p.DefaultAction)
	}
	if len(p.Syscalls) == 0 {
		return nil, errors.New("profile: no rules")
	}
	var names []string
	for i, rule := range p.Syscalls {
		if rule.Action != "SCMP_ACT_ALLOW" {
			return nil, fmt.Errorf("profile: rule %d has action %q; this loader applies only SCMP_ACT_ALLOW", i, rule.Action)
		}
		if len(rule.Names) == 0 {
			return nil, fmt.Errorf("profile: rule %d has no names", i)
		}
		names = append(names, rule.Names...)
	}
	return names, nil
}
