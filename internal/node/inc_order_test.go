package node

import (
	"crypto/ed25519"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/TAIPANBOX/rollcall/internal/deliver"
	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/roster"
)

// newMember returns a roster member named name with fresh keys, for a
// router that is added to the roster and never runs.
func newMember(t testing.TB, name string) roster.Member {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return roster.Member{ID: id.ID, Name: name, SignPub: id.Sign.Public().(ed25519.PublicKey), RecvPub: id.Recv.PublicKey().Bytes()}
}

// publish makes the primary r01 sign the roster change edit.
func (g *group) publish(edit func(r *roster.Roster)) {
	g.t.Helper()
	if err := g.nodes[0].Publish(func(r *roster.Roster) error { edit(r); return nil }); err != nil {
		g.t.Fatalf("Publish: %v", err)
	}
}

// memberIndex returns the index of the member named name in r.
func memberIndex(r *roster.Roster, name string) int {
	for i, m := range r.Members {
		if m.Name == name {
			return i
		}
	}
	panic("no member " + name)
}

// TestHeldAnnouncementsInOrder (U1, lab 2026-10-23): while the chat cannot
// be reached, a router loses its internet and then the group changes four
// times, as on the lab day: two routers added, one made the backup admin,
// one given the sender role. When the chat answers again, everything held
// goes out in the order it happened: the internet loss first, then the
// roster changes in the order of their roster versions. The chat once got
// the announcements before the loss, in the order of their incident IDs.
func TestHeldAnnouncementsInOrder(t *testing.T) {
	g := newGroup(t, setup{n: 3, senders: map[int]int{0: 1}})
	g.run(20 * sec)
	g.chat.setDown(true)
	g.nodes[2].LocalEvent(events.Event{Type: events.InternetLost})
	g.run(2 * sec)
	g.publish(func(r *roster.Roster) { r.Members = append(r.Members, newMember(t, "r04")) })
	g.run(2 * sec)
	g.publish(func(r *roster.Roster) { r.Members = append(r.Members, newMember(t, "r05")) })
	g.run(3 * sec)
	g.publish(func(r *roster.Roster) {
		i := memberIndex(r, "r04")
		r.Members[i].Roles = append(r.Members[i].Roles, roster.RoleBackup)
		r.Admins = append(r.Admins, r.Members[i].ID)
	})
	g.run(2 * sec)
	g.publish(func(r *roster.Roster) { r.Members[1].Roles = append(r.Members[1].Roles, roster.RoleSender) })
	g.run(15 * sec)
	g.chat.setDown(false)
	g.run(30 * sec)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	want := []string{"internet lost", "r04 added (by r01)", "r05 added (by r01)", "r04 is now the backup admin (by r01)", "r02 is now a sender (by r01)"}
	var got []string
	for _, m := range g.chat.all() {
		if strings.Contains(m, "internet lost") || strings.Contains(m, "the group changed") {
			got = append(got, m)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("%d held messages, want %d:\n%s", len(got), len(want), strings.Join(got, "\n"))
	}
	for i, w := range want {
		if _, rest, ok := strings.Cut(got[i], "the group changed: "); i == 0 && !strings.Contains(got[i], w) || i > 0 && (!ok || !strings.HasPrefix(rest, w)) {
			t.Fatalf("message %d is %q, want the one about %q; the order was:\n%s", i+1, got[i], w, strings.Join(got, "\n"))
		}
	}
}

// TestAnnouncementsLearntTogetherInOrder (U1): the sender is cut off while
// the primary changes the roster three times, and learns the three versions
// at once when the link heals. Its announcements, queued in one moment, go
// out in the order of their roster versions.
func TestAnnouncementsLearntTogetherInOrder(t *testing.T) {
	for range 3 { // the IDs are random: three groups make an order by ID unlikely to pass
		g := newGroup(t, setup{n: 3, senders: map[int]int{1: 1}})
		g.run(20 * sec)
		g.split([]int{1}, []int{0, 2}, true)
		g.publish(func(r *roster.Roster) { r.Members[2].Roles = append(r.Members[2].Roles, roster.RoleSender) })
		g.run(sec)
		g.publish(func(r *roster.Roster) {
			r.Members[2].Roles = append(r.Members[2].Roles, roster.RoleBackup)
			r.Admins = append(r.Admins, r.Members[2].ID)
		})
		g.run(sec)
		g.publish(func(r *roster.Roster) {
			r.Members[2].Roles = slices.DeleteFunc(r.Members[2].Roles, func(x roster.Role) bool { return x == roster.RoleSender })
		})
		g.run(sec)
		g.publish(func(r *roster.Roster) { r.Members[0].Roles = append(r.Members[0].Roles, roster.RoleSender) })
		g.run(sec)
		g.split([]int{1}, []int{0, 2}, false)
		g.run(30 * sec)
		t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
		got := g.chat.messages("the group changed: ")
		if len(got) != 4 {
			t.Fatalf("%d announcements, want 4:\n%s", len(got), strings.Join(got, "\n"))
		}
		for i, v := range []uint64{2, 3, 4, 5} {
			id := with(g.nodes[1], func() string {
				for _, r := range g.nodes[1].inc.recent {
					if r.single && r.inc.Seq == v {
						return shortID(r.inc.ID)
					}
				}
				return "none"
			})
			if !strings.Contains(got[i], "["+id+"]") {
				t.Fatalf("announcement %d is %q, want the one of roster version %d [%s]; the order was:\n%s", i+1, got[i], v, id, strings.Join(got, "\n"))
			}
			if w := []string{"r03 is now a sender", "r03 is now the backup admin", "r03 is no longer a sender", "r01 is now a sender"}[i]; !strings.Contains(got[i], "the group changed: "+w+" (by r01).") {
				t.Fatalf("announcement %d is %q, want it to say %q", i+1, got[i], w)
			}
		}
	}
}

// TestDroppedBodyRoles (U2): the record of an undone branch names the roles
// a change of roles gave and took, and a reader takes only roles this
// version knows, each once, and only on a change of roles: the body comes
// from another member's chain.
func TestDroppedBodyRoles(t *testing.T) {
	tip := `"tip":"` + strings.Repeat("ab", 32) + `"`
	cases := []struct {
		name string
		body string
		ok   bool
	}{
		{"gained and lost", `{"dropped":{` + tip + `,"changes":[{"kind":3,"member":"r02","by":"r01","gained":["primary"],"lost":["backup"]}]}}`, true},
		{"none named", `{"dropped":{` + tip + `,"changes":[{"kind":3,"member":"r02","by":"r01"}]}}`, true},
		{"an unknown role", `{"dropped":{` + tip + `,"changes":[{"kind":3,"member":"r02","by":"r01","gained":["root"]}]}}`, false},
		{"a role twice", `{"dropped":{` + tip + `,"changes":[{"kind":3,"member":"r02","by":"r01","lost":["sender","sender"]}]}}`, false},
		{"a role gained and lost", `{"dropped":{` + tip + `,"changes":[{"kind":3,"member":"r02","by":"r01","gained":["sender"],"lost":["sender"]}]}}`, false},
		{"roles on an addition", `{"dropped":{` + tip + `,"changes":[{"kind":1,"member":"r02","by":"r01","gained":["sender"]}]}}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := history.Entry{Kind: history.KindEvent, Body: []byte(c.body)}
			d, ok := decodeDropped(e)
			if ok != c.ok {
				t.Fatalf("decodeDropped = %+v, %v; want ok %v", d, ok, c.ok)
			}
		})
	}
	// What a member writes for a takeover, it reads back.
	base := roster.Roster{Members: []roster.Member{{ID: ids.MemberID{1}, Name: "r01", Roles: []roster.Role{roster.RolePrimary, roster.RoleSender}},
		{ID: ids.MemberID{2}, Name: "r02", Roles: []roster.Role{roster.RoleBackup}}}}
	next := roster.Roster{Members: []roster.Member{{ID: ids.MemberID{1}, Name: "r01", Roles: []roster.Role{roster.RoleSender, roster.RoleBackup}},
		{ID: ids.MemberID{2}, Name: "r02", Roles: []roster.Role{roster.RolePrimary}}}}
	got := diffRosters(base, next, "r02")
	want := []deliver.Change{
		{Kind: deliver.ChangeRoles, Member: "r01", By: "r02", Gained: []roster.Role{roster.RoleBackup}, Lost: []roster.Role{roster.RolePrimary}},
		{Kind: deliver.ChangeRoles, Member: "r02", By: "r02", Gained: []roster.Role{roster.RolePrimary}, Lost: []roster.Role{roster.RoleBackup}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("diffRosters = %+v, want %+v", got, want)
	}
}
