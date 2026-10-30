package deliver

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/roster"
)

// MaxMessage is the longest message, in UTF-16 code units, which is how
// Telegram counts the 4096 characters it allows in one message.
const MaxMessage = 4096

// QueueFull is the type of the notice a sender sends when its queue refused
// incidents (Queue, "A full queue"). It is never an event in the history.
const QueueFull events.Type = "queue_full"

// The words of every message, kept together so that a translation replaces
// this block and nothing else. A message is plain text: Telegram gets it
// without a parse mode, so nothing here is escaped for Markdown or HTML and
// nothing may look like markup, a link, a mention or a command.
const (
	wordSilent       = "%s stopped answering at %s"
	wordCrash        = "%s rebooted unexpectedly at %s, back after %s"
	wordCrashBack    = "%s rebooted unexpectedly, back at %s"
	wordPlanned      = "%s rebooted as planned at %s, back after %s"
	wordPlannedBack  = "%s rebooted as planned, back at %s"
	wordUpgraded     = "%s upgraded%s at %s, back after %s"
	wordUpgradedBack = "%s upgraded%s, back at %s"
	wordVersions     = " %s -> %s"
	wordLinkLost     = "%s lost contact %s to %s but stayed up: a link problem, not a reboot"
	wordLinkLostBack = "%s lost contact until %s but stayed up: a link problem, not a reboot"
	wordBack         = "%s went silent at %s, back after %s"
	wordBackOnly     = "%s answered again at %s"

	wordInternetDown = "internet was down from %s to %s (%s)"
	wordInternetLost = "internet lost at %s"
	wordInternetBack = "internet came back at %s"
	wordWanDown      = "WAN was down from %s to %s (%s)"
	wordWanLost      = "WAN went down at %s"
	wordWanBack      = "WAN came back at %s"
	wordDNSDown      = "DNS was down from %s to %s (%s)"
	wordDNSLost      = "DNS stopped answering at %s"
	wordDNSBack      = "DNS answered again at %s"
	wordDNSOnly      = "Only name lookups failed"
	wordLinksDown    = "%s were down from %s to %s (%s)"
	wordLinksLost    = "%s went down at %s"
	wordLinksBack    = "%s came back at %s"
	wordLinkWasDown  = "%s was down from %s to %s (%s)"
	wordLinksPartly  = "%s came back at %s on %s, still down on %s"
	wordFlapping     = "%s keeps dropping since %s: down %d times so far"
	wordFlappingDown = "%s went down at %s and keeps dropping: down %d times so far"
	wordOn           = "%s on %s"
	wordLinkJoin     = "; "
	wordDrops        = "%s went down %d times"
	wordDropsOn      = "%s went down %d times on %s"
	wordDropsAll     = ", %s in all"
	wordNameWAN      = "WAN"
	wordNameInternet = "internet"
	wordNameDNS      = "DNS"
	wordUplink       = "uplink switched at %s"
	wordFlood        = "a flood of packets that failed authentication reached the group at %s"
	wordSeenBy       = "Seen by %s"

	wordDuplicate       = "two devices answered as %s at %s"
	wordFork            = "%s showed different histories to different routers at %s; the proof is kept"
	wordJoined          = "%s joined the group at %s"
	wordLeft            = "%s left the group at %s"
	wordGroupChanged    = "the group changed: %s"
	wordGroupChangeAt   = "the group changed at %s"
	wordUndone          = "after the network healed, these changes were undone: %s"
	wordUndoneNone      = "after the network healed, changes made during the split were undone"
	wordUndoneRepeat    = "Repeat them if they are still wanted"
	wordAdded           = "%s added"
	wordRemoved         = "%s removed"
	wordRoles           = "%s roles changed"
	wordRolesNow        = "%s is now %s"
	wordRolesNoLonger   = "%s is no longer %s"
	wordRolesBoth       = "%s is now %s and no longer %s"
	wordRolesBecame     = "%s became %s"
	wordRolesStopped    = "%s stopped being %s"
	wordRolesBecameBoth = "%s became %s and stopped being %s"
	wordRolePrimary     = "the primary admin"
	wordRoleBackup      = "the backup admin"
	wordRoleSender      = "a sender"
	wordAnd             = " and "
	wordChanged         = "%s changed"
	wordBy              = " (by %s)"
	wordQueueFull       = "incidents were dropped: more than %d were waiting to be sent"
	wordOther           = "event %s at %s"
	wordUnknownEvent    = "an unknown event at %s"

	wordConfirmed     = ", confirmed by %d of %d"
	wordApproximate   = "Times are approximate"
	wordUnknownRouter = "an unknown router"
	wordRouter        = "router %s"
	wordList          = ", "
	wordTag           = " [%s]"
	wordCut           = "..."

	wordDays    = "%d d"
	wordHours   = "%d h"
	wordMinutes = "%d min"
	wordSeconds = "%d s"

	layoutTime     = "15:04"
	layoutDateTime = "2 Jan 15:04"
	layoutUntil    = "15:04:05"

	statusBlocked     = "bot blocked"
	statusRateLimited = "rate limited until %s"
	statusTLS         = "cannot reach Telegram securely"
	statusFailed      = "send failed: %s"
)

// Facts is what a message needs beyond the incident itself. The node gathers
// it: names from the roster, versions from the events' Detail, the count of
// confirmations from the records and witness statements in the history, and
// the changes from the rosters. Every string in it is treated as hostile: a name that is
// not a roster name and a version that is not a plain version are left out of
// the message, never repeated.
type Facts struct {
	// Names maps a member's ID, in the hex form an incident lists it in, to
	// its roster name. A member without a valid roster name here is shown as
	// "router" and the first 8 hex digits of its ID.
	Names map[string]string
	// From and To are the OpenWrt versions before and after an Upgraded
	// incident. The node fills them only when every member the incident
	// names went from From to To; both must be plain versions to be shown.
	From, To string
	// Confirmed and Of give "confirmed by Confirmed of Of": of the Of
	// members other than the absent ones, Confirmed saw the absence. The
	// count is told only on a message about a member's absence, and left out
	// unless 0 <= Confirmed <= Of and Of > 0: a router's own WAN or internet
	// is seen by no other router, and its witnesses are named ("Seen by").
	Confirmed, Of int
	// Changes are the roster changes a RosterChanged incident announces or a
	// RosterChangesDropped incident lists as undone, in the order to show.
	Changes []Change
	// Links sums up, for an incident of link changes, each kind of link in
	// it (LinksOf over its events). Without it a link incident is told from
	// its types, Start and End alone.
	Links []Link
	// Ongoing says that the chain of link changes the incident tells had not
	// gone quiet when it was made (the node's ceiling): a link of it that
	// dropped more than once is told as one that keeps dropping, not as one
	// that was down.
	Ongoing bool
}

// Link is what an incident of link changes holds of one kind of link: the
// WAN, the internet behind it, or the DNS servers its uplink names.
type Link struct {
	// Kind is the loss that names the kind: events.WanDown,
	// events.InternetLost or events.DNSLost.
	Kind events.Type
	// Lost and Back say whether the incident holds a loss and a return of
	// it. Down says whether a router's last record of it is a loss: it is
	// still down at the incident's end.
	Lost, Back, Down bool
	// Up and Still are the hex IDs of the routers whose last record of it is
	// a return, and a loss, in ID order.
	Up, Still []string
	// From is its first loss, To its last return, as the routers stamped
	// them; zero without one.
	From, To clock.Stamp
	// Drops is the most times one router saw it go down: a loss while it
	// was up or not yet known counts, a loss while it was down repeats one.
	// Of is that router's hex ID, Gone how long its drops that ended lasted
	// in all, and Ended whether every one of them ended.
	Drops int
	Of    string
	Gone  time.Duration
	Ended bool
}

// linkKinds are the kinds of link a message names, in the order it names
// them, each with its loss, its return and its name.
var linkKinds = []struct {
	loss, back events.Type
	name       string
}{
	{events.WanDown, events.WanUp, wordNameWAN},
	{events.InternetLost, events.InternetRestored, wordNameInternet},
	{events.DNSLost, events.DNSRestored, wordNameDNS},
}

// Elided is what a kept incident no longer holds of one router's link to
// keep its size bounded: Drops drops that ended, down for Gone in all, all
// of them between the router's first and last records of the link it holds.
// Kind is the link's loss, Witness the router's hex ID.
type Elided struct {
	Kind    events.Type
	Witness string
	Drops   int
	Gone    time.Duration
}

// LinksOf sums up the losses and returns of links among evs: one Link per
// kind that occurs, in the order WAN, internet, DNS. Each router's records
// of a kind are read in the order of their stamps: a loss while the link was
// up, or as its first record, opens a drop, a loss while it was down repeats
// that drop, and a return ends it. Every other event is passed over. The
// drops elided add to their router's count and time down.
func LinksOf(evs []events.Event, elided ...Elided) []Link {
	var out []Link
	for _, k := range linkKinds {
		per := map[string][]events.Event{}
		for _, e := range evs {
			if e.Type == k.loss || e.Type == k.back {
				w := e.Witness.String()
				per[w] = append(per[w], e)
			}
		}
		if len(per) == 0 {
			continue
		}
		l := Link{Kind: k.loss}
		for _, w := range slices.Sorted(maps.Keys(per)) {
			es := per[w]
			slices.SortStableFunc(es, func(a, b events.Event) int {
				if c := a.At.Wall.Compare(b.At.Wall); c != 0 {
					return c
				}
				return cmp.Compare(a.At.Mono, b.At.Mono)
			})
			down, drops := false, 0
			var since clock.Stamp
			var gone time.Duration
			for _, e := range es {
				if e.Type == k.loss {
					l.Lost = true
					if l.From == (clock.Stamp{}) || e.At.Wall.Before(l.From.Wall) {
						l.From = e.At
					}
					if !down {
						down, drops, since = true, drops+1, e.At
					}
					continue
				}
				l.Back = true
				if l.To == (clock.Stamp{}) || e.At.Wall.After(l.To.Wall) {
					l.To = e.At
				}
				if down {
					d, _ := clock.Duration(since, e.At)
					gone, down = gone+d, false
				}
			}
			for _, x := range elided {
				if x.Kind == k.loss && x.Witness == w {
					drops, gone = drops+x.Drops, gone+x.Gone
				}
			}
			l.Down = l.Down || down
			if down {
				l.Still = append(l.Still, w)
			} else {
				l.Up = append(l.Up, w)
			}
			if drops > l.Drops {
				l.Drops, l.Of, l.Gone, l.Ended = drops, w, gone, !down
			}
		}
		out = append(out, l)
	}
	return out
}

// ChangeKind is what a roster change did to a member.
type ChangeKind int

// The kinds of roster change a message names. Any other value is shown as
// "changed".
const (
	ChangeAdded   ChangeKind = iota + 1 // the member was added
	ChangeRemoved                       // the member was removed
	ChangeRoles                         // its roles changed: sender, primary or backup admin
)

// Change is one roster change and the router that signed it.
type Change struct {
	Kind   ChangeKind
	Member string // the roster name of the member changed
	By     string // the roster name of the router that signed the change; left out if empty or not a roster name
	// Gained and Lost are, for ChangeRoles, the roles the member gained
	// and lost.
	Gained, Lost []roster.Role
}

// Render returns the message that reports inc for the site, with times in tz
// (UTC if nil): one line of plain text, at most MaxMessage UTF-16 code units,
// such as
//
//	Home: ap-kitchen rebooted unexpectedly at 14:02, back after 1 min 5 s.
//
// It says what happened from the incident's types, Start and End, and names
// from f. An absence is told from its cause's return: the incident's span runs
// from Start to End, and its start is known when the incident holds the
// MemberSilent (the node pairs a return with the silence before it by merging
// the two incidents) or says that Start is when the absence began
// (Incident.Began, which Coalesce also sets when a cause's own account of its
// return gives Start from its Since). Otherwise only the return is told.
// Link changes are told for the site,
// with the members that saw them. An incident whose times are approximate,
// or whose span the clocks cannot measure exactly, says so.
//
// Render never adds markup and never escapes: Telegram receives the text with
// no parse mode. It drops every character that is not printable (line breaks,
// control and format characters, invalid UTF-8) from the whole message, and
// shows peer strings only in a form that cannot become a link, a mention or a
// command (Facts). The incident ID is not part of the text; Deliver adds it.
func Render(inc events.Incident, site string, tz *time.Location, f Facts) string {
	if tz == nil {
		tz = time.UTC
	}
	m := message{tz: tz, f: f, approximate: inc.Approximate}
	first, rest := m.describe(inc)
	var b strings.Builder
	if s := strings.TrimSpace(clean(site)); s != "" {
		b.WriteString(s)
		b.WriteString(": ")
	}
	b.WriteString(first)
	if _, ok := absenceOf(inc.Events); ok && f.Of > 0 && f.Confirmed >= 0 && f.Confirmed <= f.Of {
		fmt.Fprintf(&b, wordConfirmed, f.Confirmed, f.Of)
	}
	b.WriteString(".")
	if m.approximate {
		rest = append(rest, wordApproximate)
	}
	for _, s := range rest {
		b.WriteString(" ")
		b.WriteString(s)
		b.WriteString(".")
	}
	return cut(clean(b.String()), MaxMessage)
}

// message holds what describing one incident needs.
type message struct {
	tz          *time.Location
	f           Facts
	approximate bool
}

// describe returns the first sentence of the message, without its period,
// and the sentences after it.
func (m *message) describe(inc events.Incident) (string, []string) {
	if kind, ok := absenceOf(inc.Events); ok {
		who := wordUnknownRouter
		if n := min(max(inc.Causes, 0), len(inc.Members)); n > 0 {
			who = m.names(inc.Members[:n])
		}
		return m.absence(kind, inc.Began || has(inc.Events, events.MemberSilent), who, inc), nil
	}
	seen := m.seenBy(inc.Witnesses)
	at := m.at(inc.Start.Wall)
	if len(m.f.Links) > 0 {
		first, rest := m.links(inc, m.f.Links)
		return first, append(rest, seen...)
	}
	switch {
	case has(inc.Events, events.InternetLost) || has(inc.Events, events.InternetRestored):
		return m.change(inc, events.InternetLost, events.InternetRestored, wordInternetDown, wordInternetLost, wordInternetBack), seen
	case has(inc.Events, events.WanDown) || has(inc.Events, events.WanUp):
		return m.change(inc, events.WanDown, events.WanUp, wordWanDown, wordWanLost, wordWanBack), seen
	case has(inc.Events, events.DNSLost) || has(inc.Events, events.DNSRestored):
		return m.change(inc, events.DNSLost, events.DNSRestored, wordDNSDown, wordDNSLost, wordDNSBack), append([]string{wordDNSOnly}, seen...)
	case has(inc.Events, events.UplinkSwitched):
		return fmt.Sprintf(wordUplink, at), seen
	case has(inc.Events, events.UnderFlood):
		return fmt.Sprintf(wordFlood, at), seen
	}
	subject := wordUnknownRouter
	if len(inc.Members) > 0 {
		subject = m.name(inc.Members[0])
	}
	var typ events.Type
	if len(inc.Events) > 0 {
		typ = inc.Events[0]
	}
	switch typ {
	case events.DuplicateIdentity:
		return fmt.Sprintf(wordDuplicate, subject, at), nil
	case events.Fork:
		return fmt.Sprintf(wordFork, subject, at), nil
	case events.MemberJoined:
		return fmt.Sprintf(wordJoined, subject, at), nil
	case events.MemberLeft:
		return fmt.Sprintf(wordLeft, subject, at), nil
	case events.RosterChanged:
		if len(m.f.Changes) == 0 {
			return fmt.Sprintf(wordGroupChangeAt, at), nil
		}
		return fmt.Sprintf(wordGroupChanged, changes(m.f.Changes, false)), nil
	case events.RosterChangesDropped:
		if len(m.f.Changes) == 0 {
			return wordUndoneNone, []string{wordUndoneRepeat}
		}
		return fmt.Sprintf(wordUndone, changes(m.f.Changes, true)), []string{wordUndoneRepeat}
	case QueueFull:
		return fmt.Sprintf(wordQueueFull, MaxQueued), nil
	}
	if plainType(typ) {
		return fmt.Sprintf(wordOther, typ, at), nil
	}
	return fmt.Sprintf(wordUnknownEvent, at), nil
}

// absence tells the absence of who, of the given kind; known says whether
// the incident's Start is when the absence began.
func (m *message) absence(kind events.Type, known bool, who string, inc events.Incident) string {
	at, back := m.at(inc.Start.Wall), m.at(inc.End.Wall)
	if kind == events.MemberSilent {
		return fmt.Sprintf(wordSilent, who, at)
	}
	if !known {
		switch kind {
		case events.RebootUnplanned:
			return fmt.Sprintf(wordCrashBack, who, back)
		case events.RebootPlanned:
			return fmt.Sprintf(wordPlannedBack, who, back)
		case events.Upgraded:
			return fmt.Sprintf(wordUpgradedBack, who, m.versions(), back)
		case events.LinkLost:
			return fmt.Sprintf(wordLinkLostBack, who, back)
		default: // MemberBack
			return fmt.Sprintf(wordBackOnly, who, back)
		}
	}
	took := m.duration(inc.Start, inc.End)
	switch kind {
	case events.RebootUnplanned:
		return fmt.Sprintf(wordCrash, who, at, took)
	case events.RebootPlanned:
		return fmt.Sprintf(wordPlanned, who, at, took)
	case events.Upgraded:
		return fmt.Sprintf(wordUpgraded, who, m.versions(), at, took)
	case events.LinkLost:
		from, to := m.span(inc.Start.Wall, inc.End.Wall)
		return fmt.Sprintf(wordLinkLost, who, from, to)
	default: // MemberBack
		return fmt.Sprintf(wordBack, who, at, took)
	}
}

// links tells an incident of link changes from its summary ls (LinksOf): in
// one sentence the links that keep dropping (Facts.Ongoing), the links that
// went down and came back, the links still down, and the links that came
// back without their loss in the incident; then a
// sentence for each link one router saw go down more than once, with the
// count and, when every drop ended, how long they lasted in all; then, when
// only DNS failed, that only name lookups did.
//
// When every link is in one of the three states, the sentence takes its
// moments from the incident's Start and End, which Coalesce places on the
// corrected clocks. A mixed incident, or links that went down further apart
// than events.LinkWindow, tells each link at its own moments.
func (m *message) links(inc events.Incident, ls []Link) (string, []string) {
	var was, down, back, partly, flapping []Link
	for _, l := range ls {
		switch {
		case m.f.Ongoing && l.Drops > 1:
			flapping = append(flapping, l)
		case l.Down && len(l.Up) > 0:
			partly = append(partly, l)
		case l.Down:
			down = append(down, l)
		case l.Lost:
			was = append(was, l)
		default:
			back = append(back, l)
		}
	}
	states := 0
	for _, s := range [][]Link{was, down, back, partly, flapping} {
		if len(s) > 0 {
			states++
		}
	}
	one := states == 1
	var parts []string
	for _, l := range flapping {
		name := linkName(l.Kind)
		if len(inc.Witnesses) > 1 {
			name = fmt.Sprintf(wordOn, name, m.name(l.Of))
		}
		if slices.Contains(l.Still, l.Of) { // the router that keeps dropping it is down for now
			parts = append(parts, fmt.Sprintf(wordFlappingDown, name, m.at(l.From.Wall), l.Drops))
			continue
		}
		parts = append(parts, fmt.Sprintf(wordFlapping, name, m.at(l.From.Wall), l.Drops)+fmt.Sprintf(wordDropsAll, durationText(l.Gone)))
	}
	if len(was) > 0 {
		parts = append(parts, m.linksWere(inc, was, one))
	}
	if len(down) > 0 {
		at := inc.Start
		if !one {
			at = earliestFrom(down)
		}
		parts = append(parts, linksSentence(down, wordLinksLost, map[events.Type]string{
			events.WanDown: wordWanLost, events.InternetLost: wordInternetLost, events.DNSLost: wordDNSLost}, m.at(at.Wall)))
	}
	if len(back) > 0 {
		at := inc.End
		if !one {
			at = latestTo(back)
		}
		parts = append(parts, linksSentence(back, wordLinksBack, map[events.Type]string{
			events.WanDown: wordWanBack, events.InternetLost: wordInternetBack, events.DNSLost: wordDNSBack}, m.at(at.Wall)))
	}
	parts = append(parts, m.linksPartly(partly)...)
	var rest []string
	dnsOnly := true
	for _, l := range ls {
		if l.Kind != events.DNSLost {
			dnsOnly = false
		}
		if l.Drops < 2 || slices.ContainsFunc(flapping, func(f Link) bool { return f.Kind == l.Kind }) {
			continue // a flapping link is counted in the first sentence
		}
		name := capitalized(linkName(l.Kind))
		s := fmt.Sprintf(wordDrops, name, l.Drops)
		if len(inc.Witnesses) > 1 {
			s = fmt.Sprintf(wordDropsOn, name, l.Drops, m.name(l.Of))
		}
		if l.Ended {
			s += fmt.Sprintf(wordDropsAll, durationText(l.Gone))
		}
		rest = append(rest, s)
	}
	if dnsOnly && slices.ContainsFunc(ls, func(l Link) bool { return l.Kind == events.DNSLost }) {
		rest = append(rest, wordDNSOnly)
	}
	return strings.Join(parts, wordLinkJoin), rest
}

// linksWere tells the links that went down and came back: together, from
// the first loss to the last return, when they went down within
// events.LinkWindow of each other, else each with its own span. one says
// that every link of the incident is among them, so the span is the
// incident's own.
func (m *message) linksWere(inc events.Incident, ls []Link, one bool) string {
	together := true
	for _, l := range ls {
		if d := l.From.Wall.Sub(ls[0].From.Wall); d > events.LinkWindow || d < -events.LinkWindow {
			together = false
		}
	}
	if together {
		from, to := inc.Start, inc.End
		if !one {
			from, to = earliestFrom(ls), latestTo(ls)
		}
		a, b := m.span(from.Wall, to.Wall)
		took := m.duration(from, to)
		if len(ls) == 1 {
			return fmt.Sprintf(wordLinkWasDown, linkName(ls[0].Kind), a, b, took)
		}
		return fmt.Sprintf(wordLinksDown, linkNames(ls), a, b, took)
	}
	var out []string
	for _, l := range ls {
		a, b := m.span(l.From.Wall, l.To.Wall)
		out = append(out, fmt.Sprintf(wordLinkWasDown, linkName(l.Kind), a, b, m.duration(l.From, l.To)))
	}
	return strings.Join(out, wordList)
}

// linksPartly tells the links that came back on some routers and are still
// down on others: one phrase for the links that share both lists of routers,
// at the last return among them.
func (m *message) linksPartly(ls []Link) []string {
	var out []string
	done := make([]bool, len(ls))
	for i, l := range ls {
		if done[i] {
			continue
		}
		same := []Link{l}
		for j := i + 1; j < len(ls); j++ {
			if !done[j] && slices.Equal(ls[j].Up, l.Up) && slices.Equal(ls[j].Still, l.Still) {
				same, done[j] = append(same, ls[j]), true
			}
		}
		out = append(out, fmt.Sprintf(wordLinksPartly, linkNames(same), m.at(latestTo(same).Wall), m.names(l.Up), m.names(l.Still)))
	}
	return out
}

// linksSentence tells links that went down (or came back) at one moment: a
// single link in its own words, several by their names.
func linksSentence(ls []Link, several string, single map[events.Type]string, at string) string {
	if len(ls) == 1 {
		return fmt.Sprintf(single[ls[0].Kind], at)
	}
	return fmt.Sprintf(several, linkNames(ls), at)
}

func earliestFrom(ls []Link) clock.Stamp {
	s := ls[0].From
	for _, l := range ls[1:] {
		if l.From.Wall.Before(s.Wall) {
			s = l.From
		}
	}
	return s
}

func latestTo(ls []Link) clock.Stamp {
	s := ls[0].To
	for _, l := range ls[1:] {
		if l.To.Wall.After(s.Wall) {
			s = l.To
		}
	}
	return s
}

// linkName is the name a message gives a kind of link.
func linkName(kind events.Type) string {
	for _, k := range linkKinds {
		if k.loss == kind {
			return k.name
		}
	}
	return string(kind)
}

// linkNames joins the names of the links: "WAN and internet", "WAN,
// internet and DNS".
func linkNames(ls []Link) string {
	names := make([]string, len(ls))
	for i, l := range ls {
		names[i] = linkName(l.Kind)
	}
	if len(names) == 1 {
		return names[0]
	}
	return strings.Join(names[:len(names)-1], wordList) + wordAnd + names[len(names)-1]
}

// capitalized returns s with its first letter upper case, to start a
// sentence.
func capitalized(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	return string(unicode.ToUpper(r)) + s[n:]
}

// change tells a link change: lost and back with the span, or one of them.
func (m *message) change(inc events.Incident, lost, back events.Type, both, onlyLost, onlyBack string) string {
	switch {
	case has(inc.Events, lost) && has(inc.Events, back):
		from, to := m.span(inc.Start.Wall, inc.End.Wall)
		return fmt.Sprintf(both, from, to, m.duration(inc.Start, inc.End))
	case has(inc.Events, lost):
		return fmt.Sprintf(onlyLost, m.at(inc.Start.Wall))
	default:
		return fmt.Sprintf(onlyBack, m.at(inc.End.Wall))
	}
}

// absenceOf returns the absence an incident reports: the strongest return
// it holds (Upgraded, then RebootUnplanned, RebootPlanned, LinkLost,
// MemberBack), else MemberSilent; false if it holds no absence.
func absenceOf(types []events.Type) (events.Type, bool) {
	for _, t := range []events.Type{events.Upgraded, events.RebootUnplanned, events.RebootPlanned, events.LinkLost, events.MemberBack, events.MemberSilent} {
		if has(types, t) {
			return t, true
		}
	}
	return "", false
}

func has(types []events.Type, t events.Type) bool {
	for _, x := range types {
		if x == t {
			return true
		}
	}
	return false
}

// versions returns " From -> To" when both are plain versions, else "".
func (m *message) versions() string {
	if plainVersion(m.f.From) && plainVersion(m.f.To) {
		return fmt.Sprintf(wordVersions, m.f.From, m.f.To)
	}
	return ""
}

// seenBy returns the sentence naming the witnesses, or nothing without any.
func (m *message) seenBy(witnesses []string) []string {
	if len(witnesses) == 0 {
		return nil
	}
	return []string{fmt.Sprintf(wordSeenBy, m.names(witnesses))}
}

func (m *message) names(hexIDs []string) string {
	out := make([]string, len(hexIDs))
	for i, h := range hexIDs {
		out[i] = m.name(h)
	}
	return strings.Join(out, wordList)
}

// name returns the roster name of the member whose hex ID is h, or what
// stands for a member without one.
func (m *message) name(h string) string {
	if !isHex(h, 32) {
		return wordUnknownRouter
	}
	if n, ok := m.f.Names[h]; ok && roster.ValidName(n) == nil {
		return n
	}
	return fmt.Sprintf(wordRouter, h[:8])
}

// changes lists roster changes, each with the router that signed it: as
// they stand now, or, when undone, as what was done.
func changes(cs []Change, undone bool) string {
	out := make([]string, len(cs))
	for i, c := range cs {
		who := wordUnknownRouter
		if roster.ValidName(c.Member) == nil {
			who = c.Member
		}
		switch c.Kind {
		case ChangeAdded:
			out[i] = fmt.Sprintf(wordAdded, who)
		case ChangeRemoved:
			out[i] = fmt.Sprintf(wordRemoved, who)
		case ChangeRoles:
			out[i] = roleChange(who, c.Gained, c.Lost, undone)
		default:
			out[i] = fmt.Sprintf(wordChanged, who)
		}
		if roster.ValidName(c.By) == nil {
			out[i] += fmt.Sprintf(wordBy, c.By)
		}
	}
	return strings.Join(out, wordList)
}

// roleChange tells which roles who gained and lost: "is now a sender",
// "is no longer the backup admin", or, for a change undone, "became a
// sender", "stopped being the backup admin". Only the roles this version
// knows are named, each once; without any it says the roles changed.
func roleChange(who string, gained, lost []roster.Role, undone bool) string {
	g, l := roleNames(gained), roleNames(lost)
	both, onlyGained, onlyLost := wordRolesBoth, wordRolesNow, wordRolesNoLonger
	if undone {
		both, onlyGained, onlyLost = wordRolesBecameBoth, wordRolesBecame, wordRolesStopped
	}
	switch {
	case g != "" && l != "":
		return fmt.Sprintf(both, who, g, l)
	case g != "":
		return fmt.Sprintf(onlyGained, who, g)
	case l != "":
		return fmt.Sprintf(onlyLost, who, l)
	}
	return fmt.Sprintf(wordRoles, who)
}

// roleNames names the roles in rs that this version knows, primary, backup
// and sender in that order, each once, joined by "and".
func roleNames(rs []roster.Role) string {
	var out []string
	for _, r := range []struct {
		role roster.Role
		word string
	}{{roster.RolePrimary, wordRolePrimary}, {roster.RoleBackup, wordRoleBackup}, {roster.RoleSender, wordRoleSender}} {
		if slices.Contains(rs, r.role) {
			out = append(out, r.word)
		}
	}
	return strings.Join(out, wordAnd)
}

// at formats one moment.
func (m *message) at(t time.Time) string { return t.In(m.tz).Format(layoutTime) }

// span formats the two ends of a span, with their dates when they fall on
// different days.
func (m *message) span(a, b time.Time) (string, string) {
	a, b = a.In(m.tz), b.In(m.tz)
	ay, am, ad := a.Date()
	by, bm, bd := b.Date()
	if ay != by || am != bm || ad != bd {
		return a.Format(layoutDateTime), b.Format(layoutDateTime)
	}
	return a.Format(layoutTime), b.Format(layoutTime)
}

// duration formats how long the span from a to b lasted, and notes when the
// clocks can give it only approximately.
func (m *message) duration(a, b clock.Stamp) string {
	d, approximate := clock.Duration(a, b)
	if approximate {
		m.approximate = true
	}
	return durationText(d)
}

// durationText formats d for a reader: seconds under a minute, minutes and
// seconds under an hour, then hours and minutes, then days and hours, each
// rounded to its smallest unit and without a unit that is zero.
func durationText(d time.Duration) string {
	d = max(d, 0)
	if r := d.Round(time.Second); r < time.Minute {
		return fmt.Sprintf(wordSeconds, r/time.Second)
	} else if r < time.Hour {
		return units(wordMinutes, int64(r/time.Minute), wordSeconds, int64(r%time.Minute/time.Second))
	}
	if r := d.Round(time.Minute); r < 24*time.Hour {
		return units(wordHours, int64(r/time.Hour), wordMinutes, int64(r%time.Hour/time.Minute))
	}
	r := d.Round(time.Hour)
	return units(wordDays, int64(r/(24*time.Hour)), wordHours, int64(r%(24*time.Hour)/time.Hour))
}

func units(big string, n int64, small string, k int64) string {
	if k == 0 {
		return fmt.Sprintf(big, n)
	}
	return fmt.Sprintf(big, n) + " " + fmt.Sprintf(small, k)
}

// plainVersion reports whether v can be shown as an OpenWrt version: 1 to 32
// characters from A-Z, a-z, 0-9, '-', '_' and '.', starting with a letter or
// a digit, with every '.' between two digits ("25.12.4", "24.10.0-rc1",
// "SNAPSHOT", "r28427-6df0e3d02a"). A peer chooses its version string, and
// this keeps it from naming a host ("evil.example"), a mention, a command or
// anything else Telegram would turn into an entity.
func plainVersion(v string) bool {
	if v == "" || len(v) > 32 {
		return false
	}
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case isAlnum(c):
		case c == '-' || c == '_':
			if i == 0 {
				return false
			}
		case c == '.':
			if i == 0 || i == len(v)-1 || !isDigit(v[i-1]) || !isDigit(v[i+1]) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// plainType reports whether an event type this version does not know can be
// shown: 1 to 32 characters from a-z and '_', starting with a letter.
func plainType(t events.Type) bool {
	if len(t) == 0 || len(t) > 32 || t[0] < 'a' || t[0] > 'z' {
		return false
	}
	for i := 0; i < len(t); i++ {
		if c := t[i]; !('a' <= c && c <= 'z' || c == '_') {
			return false
		}
	}
	return true
}

func isDigit(c byte) bool { return '0' <= c && c <= '9' }

func isAlnum(c byte) bool { return isDigit(c) || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }

// isHex reports whether s is n lowercase hex digits.
func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !isDigit(c) && !('a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

// clean drops from s every byte of invalid UTF-8 and every character that is
// not printable: line breaks, tabs, control and format characters (such as
// bidirectional overrides and zero-width spaces). The ASCII space stays.
func clean(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		i += n
		if r == utf8.RuneError && n == 1 {
			continue
		}
		if unicode.IsPrint(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// units16 is the length of s in UTF-16 code units.
func units16(s string) int {
	n := 0
	for _, r := range s {
		n += utf16.RuneLen(r)
	}
	return n
}

// cut returns s if it fits in limit UTF-16 code units, else its longest
// prefix that fits with "..." after it, cut between two characters.
func cut(s string, limit int) string {
	if units16(s) <= limit {
		return s
	}
	budget := limit - units16(wordCut)
	n, end := 0, len(s)
	for i, r := range s {
		if n += utf16.RuneLen(r); n > budget {
			end = i
			break
		}
	}
	return s[:end] + wordCut
}

// tag returns text with the first 8 digits of the incident ID after it,
// cleaned and cut so that the whole stays within MaxMessage. The ID makes a
// duplicate sent after a network split obvious (design 4.5).
func tag(text, id string) string {
	suffix := fmt.Sprintf(wordTag, id[:min(len(id), 8)])
	return cut(clean(text), MaxMessage-units16(suffix)) + suffix
}
