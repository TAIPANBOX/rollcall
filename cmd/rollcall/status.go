package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/TAIPANBOX/rollcall/internal/control"
)

// notRunning is the report of luci-app-rollcall/STATUS-JSON.md when the
// daemon does not answer.
type notRunning struct {
	Schema  int    `json:"schema"`
	Running bool   `json:"running"`
	Error   string `json:"error"`
}

// status prints the daemon's report: with --json exactly as rollcalld
// wrote it, one object; otherwise as a few lines for a person. It exits 1
// when the daemon does not answer.
func (c *cli) status(args []string) int {
	asJSON := jsonRequested(args)
	p, err := parse(args, nil, nil)
	if err == nil {
		err = p.noWords()
	}
	if err != nil {
		if asJSON {
			c.printJSON(notRunning{Schema: 1, Error: err.Error()})
			return 1
		}
		fmt.Fprintf(c.stderr, "rollcall: %s\n", err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout("status"))
	defer cancel()
	out, err := c.call(ctx, "status")
	// A refusal comes from a daemon that runs; anything else means it did
	// not answer.
	var refused *control.Error
	running := errors.As(err, &refused)
	if err == nil && !isObject(out) {
		err, running = errors.New("rollcalld gave a status this rollcall does not read"), true
	} else if err != nil {
		err = callErr(err)
	}
	if err != nil {
		if p.json {
			c.printJSON(notRunning{Schema: 1, Running: running, Error: err.Error()})
		} else {
			fmt.Fprintf(c.stderr, "rollcall: %s\n", err)
		}
		return 1
	}
	if p.json {
		fmt.Fprintf(c.stdout, "%s\n", bytes.TrimSpace(out))
		return 0
	}
	c.printStatus(out)
	return 0
}

// isObject reports whether b is exactly one JSON object.
func isObject(b []byte) bool {
	var m map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(b))
	if dec.Decode(&m) != nil || m == nil {
		return false
	}
	_, err := dec.Token()
	return err != nil
}

// textStatus is what the text form of status reads of the report.
type textStatus struct {
	Initialised bool   `json:"initialised"`
	Error       string `json:"error"`
	Site        string `json:"site"`
	Self        *struct {
		Name     string   `json:"name"`
		Roles    []string `json:"roles"`
		Takeover bool     `json:"takeover"`
	} `json:"self"`
	Confirmation *textConfirmation `json:"confirmation"`
	Members      []struct {
		Name            string   `json:"name"`
		Roles           []string `json:"roles"`
		State           string   `json:"state"`
		LastSeenSeconds *int64   `json:"last_seen_seconds"`
	} `json:"members"`
	Sender    *string `json:"sender"`
	Incidents []struct {
		Time      string `json:"time"`
		Text      string `json:"text"`
		Delivered bool   `json:"delivered"`
	} `json:"incidents"`
	Telegram struct {
		State string `json:"state"`
	} `json:"telegram"`
	Sandbox struct {
		State string `json:"state"`
	} `json:"sandbox"`
	Storage struct {
		OK    bool    `json:"ok"`
		Error *string `json:"error"`
	} `json:"storage"`
	UnderFlood bool `json:"under_flood"`
}

func (c *cli) printStatus(out []byte) {
	var s textStatus
	_ = json.Unmarshal(out, &s)
	w := c.stdout
	if !s.Initialised {
		fmt.Fprintln(w, "rollcalld is running; this router is not set up. Run rollcall init on the first router, or rollcall join on the others.")
		if s.Error != "" {
			fmt.Fprintf(w, "Reason: %s\n", s.Error)
		}
		return
	}
	self := ""
	if s.Self != nil {
		self = s.Self.Name
	}
	fmt.Fprintf(w, "Site %s, this router %s.\n", s.Site, self)
	if s.Self != nil && s.Self.Takeover {
		fmt.Fprintln(w, "A takeover by this router is provisional until rollcall admin confirm runs here.")
	}
	if line := confirmationLine(s.Confirmation); line != "" {
		fmt.Fprintln(w, line)
	}
	fmt.Fprintln(w, "Members:")
	for _, m := range s.Members {
		line := fmt.Sprintf("  %-32s %-10s %s", m.Name, m.State, strings.Join(m.Roles, ","))
		if m.LastSeenSeconds != nil && *m.LastSeenSeconds > 0 {
			line += fmt.Sprintf("  last heard %d s ago", *m.LastSeenSeconds)
		}
		fmt.Fprintln(w, strings.TrimRight(line, " "))
	}
	sender := "none can reach Telegram"
	if s.Sender != nil {
		sender = *s.Sender
	}
	fmt.Fprintf(w, "Sender: %s. Telegram on this router: %s. Sandbox: %s.\n", sender, s.Telegram.State, s.Sandbox.State)
	if !s.Storage.OK && s.Storage.Error != nil {
		fmt.Fprintf(w, "Storage: %s\n", *s.Storage.Error)
	}
	if s.UnderFlood {
		fmt.Fprintln(w, "Under a flood: many packets that fail authentication are arriving here. They are dropped; members may look silent while it lasts, and that is reported.")
	}
	for i, inc := range s.Incidents {
		if i == 5 {
			break
		}
		mark := ""
		if !inc.Delivered {
			mark = " (waiting to be sent)"
		}
		fmt.Fprintf(w, "%s  %s%s\n", inc.Time, inc.Text, mark)
	}
}

// textConfirmation is what the text form reads of the confirmation of a
// takeover made here (security spec 6.1).
type textConfirmation struct {
	State string  `json:"state"`
	Of    *string `json:"of"`
	From  *string `json:"from"`
}

// confirmationLine says what became of a confirmation of a takeover made
// here: held until the replaced primary has been silent for a day, or
// lapsed. It is empty when there is none.
func confirmationLine(c *textConfirmation) string {
	if c == nil {
		return ""
	}
	switch c.State {
	case "held":
		from, of := "an unknown time", "the former primary"
		if c.From != nil {
			from = *c.From
		}
		if c.Of != nil && *c.Of != "" {
			of = *c.Of
		}
		return fmt.Sprintf("Confirmation of the takeover waits until %s, a day after %s was last heard; it lapses if %s is heard before.", from, of, of)
	case "lapsed":
		return "Confirmation of the takeover lapsed: the former primary was heard, or the takeover ended, before a day of silence."
	}
	return ""
}
