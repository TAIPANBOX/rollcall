package transport

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeNet is the interface source the transport reads, under the test's
// control: which devices exist, under which index, with which addresses.
// The devices are the real loopback interface, so the sockets bind for real;
// only what the kernel would report about it changes.
type fakeNet struct {
	mu    sync.Mutex
	index map[string]int          // a device missing here does not exist
	addrs map[string][]netip.Addr // the device's addresses, without zones
	asked map[string]bool         // every device name looked up
	joins []int                   // ifindex of every group join
	mcIfs []int                   // ifindex of every outgoing multicast interface set
}

// installFakeNet makes the transport read interfaces from a fakeNet until
// the test ends. The group join and the multicast interface are recorded and
// succeed, so an index the kernel does not know can stand for a recreated
// device.
func installFakeNet(t *testing.T) *fakeNet {
	t.Helper()
	f := &fakeNet{index: map[string]int{}, addrs: map[string][]netip.Addr{}, asked: map[string]bool{}}
	origLookup, origAddrs, origJoin, origMcIf := lookupIface, ifaceAddrs, joinGroupFn, multicastIfFn
	lookupIface = func(name string) (*net.Interface, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.asked[name] = true
		idx, ok := f.index[name]
		if !ok {
			return nil, fmt.Errorf("route ip+net: no such network interface %s (fake)", name)
		}
		return &net.Interface{Index: idx, Name: name, Flags: net.FlagUp | net.FlagMulticast}, nil
	}
	ifaceAddrs = func(ifi *net.Interface) ([]net.Addr, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var out []net.Addr
		for _, a := range f.addrs[ifi.Name] {
			out = append(out, &net.IPNet{IP: a.AsSlice(), Mask: net.CIDRMask(a.BitLen(), a.BitLen())})
		}
		return out, nil
	}
	joinGroupFn = func(_, ifindex int) error {
		f.mu.Lock()
		f.joins = append(f.joins, ifindex)
		f.mu.Unlock()
		return nil
	}
	multicastIfFn = func(_, ifindex int) error {
		f.mu.Lock()
		f.mcIfs = append(f.mcIfs, ifindex)
		f.mu.Unlock()
		return nil
	}
	t.Cleanup(func() {
		lookupIface, ifaceAddrs, joinGroupFn, multicastIfFn = origLookup, origAddrs, origJoin, origMcIf
	})
	return f
}

func (f *fakeNet) set(name string, index int, addrs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if index == 0 {
		delete(f.index, name)
		delete(f.addrs, name)
		return
	}
	f.index[name] = index
	f.addrs[name] = nil
	for _, a := range addrs {
		f.addrs[name] = append(f.addrs[name], netip.MustParseAddr(a))
	}
}

func (f *fakeNet) joined() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.joins)
}

// realIndex is the loopback interface's name and real index; the test skips
// when the loopback interface lacks one of the addresses it needs.
func realIndex(t *testing.T, need ...string) (string, int) {
	t.Helper()
	name := loopbackName(t)
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range need {
		if !hasAddr(t, name, netip.MustParseAddr(a)) {
			t.Skipf("no %s on %s", a, name)
		}
	}
	return name, ifi.Index
}

// eventually polls cond for up to 3 s.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within 3 s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// boundSet is the set of addresses (without zones) the transport listens on,
// with the group left out.
func boundSet(tr *Transport) map[netip.Addr]bool {
	out := map[netip.Addr]bool{}
	for _, ap := range tr.boundAddrs() {
		if a := ap.Addr().WithZone(""); a != group {
			out[a] = true
		}
	}
	return out
}

// udpReaches reports whether a datagram to ap reaches onPacket (through got)
// within wait.
func udpReaches(t *testing.T, ap netip.AddrPort, got <-chan received, wait time.Duration) bool {
	t.Helper()
	c, err := net.Dial("udp", ap.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tag := "probe-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	if _, err := c.Write([]byte(tag)); err != nil {
		return false
	}
	timeout := time.After(wait)
	for {
		select {
		case r := <-got:
			if string(r.b) == tag {
				return true
			}
		case <-timeout:
			return false
		}
	}
}

func collect(t *testing.T, tr *Transport) <-chan received {
	got := make(chan received, 64)
	serve(t, tr, func(from netip.AddrPort, b []byte) {
		select {
		case got <- received{from, append([]byte(nil), b...)}:
		default:
		}
	}, echo)
	return got
}

// TestAddressArrivingLaterIsBound is I3 (a): an address that appears on a
// peer-zone device after the start (wan's DHCP or PPPoE lease after START=95)
// gets its sockets on the next pass, and one that leaves loses them: the
// transport listens on exactly what the configured devices carry now.
func TestAddressArrivingLaterIsBound(t *testing.T) {
	lo, idx := realIndex(t, "127.0.0.1", "::1")
	f := installFakeNet(t)
	f.set(lo, idx, "::1")
	port := freePort(t)
	tr, err := Open(port, []string{lo}, allowAll)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { tr.Close() })
	got := collect(t, tr)
	v4 := loop4(port)

	if _, err := tr.Stream(v4, []byte("x")); err == nil {
		t.Fatal("Stream to 127.0.0.1 answered before the address was on the device")
	}
	f.set(lo, idx, "::1", "127.0.0.1")
	tr.Refresh()
	eventually(t, "127.0.0.1 bound after it appeared", func() bool { return boundSet(tr)[v4.Addr()] })
	if reply, err := tr.Stream(v4, []byte("late")); err != nil || string(reply) != "re:late" {
		t.Fatalf("Stream to the late address = %q, %v", reply, err)
	}
	if !udpReaches(t, v4, got, 2*time.Second) {
		t.Fatal("a datagram to the late address did not reach onPacket")
	}
	if st := tr.Devices()[lo]; st.Err != nil || len(st.Addrs) != 2 {
		t.Fatalf("Devices()[%s] = %+v, want both addresses bound and no error", lo, st)
	}

	// The address leaves the device: its sockets close.
	f.set(lo, idx, "::1")
	tr.Refresh()
	eventually(t, "127.0.0.1 unbound after it left", func() bool { return !boundSet(tr)[v4.Addr()] })
	if _, err := tr.Stream(v4, []byte("x")); err == nil {
		t.Fatal("Stream to 127.0.0.1 answered after the address left the device")
	}
	if want := map[netip.Addr]bool{netip.MustParseAddr("::1"): true}; !mapsEqual(boundSet(tr), want) {
		t.Fatalf("bound %v, want exactly %v", boundSet(tr), want)
	}
	for name := range f.asked {
		if name != lo {
			t.Fatalf("the transport looked up %q, which is no configured device", name)
		}
	}
}

func mapsEqual(a, b map[netip.Addr]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// TestRecreatedDeviceIsRebound is I3 (b): "network restart" recreates
// br-lan under a new index. The sockets pinned to the old index and the
// ff02::114 membership on it are dead, so every socket of the device is
// closed and bound again on the new index, and the group is joined there.
func TestRecreatedDeviceIsRebound(t *testing.T) {
	lo, idx := realIndex(t, "127.0.0.1")
	f := installFakeNet(t)
	f.set(lo, idx, "127.0.0.1", "fe80::1") // the link-local address makes a group socket
	port := freePort(t)
	tr, err := Open(port, []string{lo}, allowAll)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { tr.Close() })
	got := collect(t, tr)
	before := tr.sockets()
	if !slices.Contains(f.joined(), idx) {
		t.Fatalf("group joins %v, want one on index %d", f.joined(), idx)
	}

	newIdx := idx + 1000
	f.set(lo, newIdx, "127.0.0.1", "fe80::1")
	tr.Refresh()
	eventually(t, "sockets on the new index", func() bool {
		for _, s := range tr.sockets() {
			if s.ifindex != newIdx {
				return false
			}
		}
		return len(tr.sockets()) > 0
	})
	if !slices.Contains(f.joined(), newIdx) {
		t.Fatalf("group joins %v, want one on the new index %d", f.joined(), newIdx)
	}
	for _, old := range before {
		if slices.Contains(tr.sockets(), old) {
			t.Fatalf("socket %+v of the old index is still held", old)
		}
	}
	if st := tr.Devices()[lo]; st.Index != newIdx || !st.Group {
		t.Fatalf("Devices()[%s] = %+v, want index %d with the group joined", lo, st, newIdx)
	}
	if !udpReaches(t, loop4(port), got, 2*time.Second) {
		t.Fatal("a datagram after the rebind did not reach onPacket")
	}
}

// TestMissingDeviceIsNotFatal is I3 (c): a peer-zone device that does not
// exist yet (wg0 not up) is reported, the others are served, and the device
// is bound once it appears.
func TestMissingDeviceIsNotFatal(t *testing.T) {
	lo, idx := realIndex(t, "127.0.0.1")
	f := installFakeNet(t)
	f.set(lo, idx, "127.0.0.1")
	const wg = "wg0-missing"
	port := freePort(t)
	tr, err := Open(port, []string{lo, wg}, allowAll)
	if err != nil {
		t.Fatalf("Open with one device missing: %v", err)
	}
	t.Cleanup(func() { tr.Close() })
	collect(t, tr)
	if reply, err := tr.Stream(loop4(port), []byte("lan")); err != nil || string(reply) != "re:lan" {
		t.Fatalf("Stream on the present device = %q, %v", reply, err)
	}
	devs := tr.Devices()
	if devs[wg].Err == nil || !strings.Contains(devs[wg].Err.Error(), wg) {
		t.Fatalf("Devices()[%s] = %+v, want an error naming the missing device", wg, devs[wg])
	}
	if devs[lo].Err != nil {
		t.Fatalf("Devices()[%s] = %+v, want no error", lo, devs[lo])
	}
}

// TestDeviceAppearingLaterIsBound: every device missing at the start leaves
// the transport open with nothing bound; the device is bound when it shows up.
func TestDeviceAppearingLaterIsBound(t *testing.T) {
	lo, idx := realIndex(t, "127.0.0.1")
	f := installFakeNet(t)
	port := freePort(t)
	tr, err := Open(port, []string{lo}, allowAll)
	if err != nil {
		t.Fatalf("Open before the device exists: %v", err)
	}
	t.Cleanup(func() { tr.Close() })
	collect(t, tr)
	if len(tr.boundAddrs()) != 0 || tr.Devices()[lo].Err == nil {
		t.Fatalf("bound %v, status %+v; want nothing bound and the device reported", tr.boundAddrs(), tr.Devices()[lo])
	}
	f.set(lo, idx, "127.0.0.1")
	tr.Refresh()
	eventually(t, "device bound once it exists", func() bool { return boundSet(tr)[loop4(port).Addr()] })
	if reply, err := tr.Stream(loop4(port), []byte("up")); err != nil || string(reply) != "re:up" {
		t.Fatalf("Stream once the device exists = %q, %v", reply, err)
	}
	if st := tr.Devices()[lo]; st.Err != nil || st.Index != idx {
		t.Fatalf("Devices()[%s] = %+v, want index %d and no error", lo, st, idx)
	}
}

// TestUnbindableAddressIsNotFatal is I3 (c): an address the kernel will not
// bind (tentative, or dadfailed because a LAN device answered the duplicate
// address check) is reported; the device's other addresses are served.
// ListenPeers keeps its all-or-nothing contract.
func TestUnbindableAddressIsNotFatal(t *testing.T) {
	lo, idx := realIndex(t, "127.0.0.1")
	f := installFakeNet(t)
	const bad = "2001:db8::7"        // not on the host: bind fails as for a dadfailed address
	f.set(lo, idx, bad, "127.0.0.1") // the failing one first: it must not stop the pass
	port := freePort(t)
	tr, err := Open(port, []string{lo}, allowAll)
	if err != nil {
		t.Fatalf("Open with an unbindable address: %v", err)
	}
	t.Cleanup(func() { tr.Close() })
	collect(t, tr)
	if reply, err := tr.Stream(loop4(port), []byte("ok")); err != nil || string(reply) != "re:ok" {
		t.Fatalf("Stream on the bindable address = %q, %v", reply, err)
	}
	st := tr.Devices()[lo]
	if st.Err == nil || !strings.Contains(st.Err.Error(), bad) {
		t.Fatalf("Devices()[%s] = %+v, want an error naming %s", lo, st, bad)
	}
	if !slices.Equal(st.Addrs, []netip.Addr{netip.MustParseAddr("127.0.0.1")}) {
		t.Fatalf("Devices()[%s].Addrs = %v, want [127.0.0.1]", lo, st.Addrs)
	}

	if tr2, err := ListenPeers(freePort(t), []string{lo}, allowAll); err == nil {
		tr2.Close()
		t.Fatal("ListenPeers bound a device with an unbindable address; it binds all or nothing")
	}
}

// TestPeriodicPassWithoutEvent: no hotplug event arrives (DAD ends, an
// address is renumbered); the periodic pass binds the new address.
func TestPeriodicPassWithoutEvent(t *testing.T) {
	lo, idx := realIndex(t, "127.0.0.1", "::1")
	f := installFakeNet(t)
	f.set(lo, idx, "::1")
	port := freePort(t)
	tr, err := Open(port, []string{lo}, allowAll)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { tr.Close() })
	tr.every = 20 * time.Millisecond
	collect(t, tr)
	f.set(lo, idx, "::1", "127.0.0.1")
	eventually(t, "127.0.0.1 bound by the periodic pass", func() bool { return boundSet(tr)[loop4(port).Addr()] })
}

// TestOpenRejectsBadInput: Open refuses what no pass can fix.
func TestOpenRejectsBadInput(t *testing.T) {
	lo := loopbackName(t)
	for _, c := range []struct {
		name   string
		port   int
		ifaces []string
		auth   func([]byte) bool
	}{
		{"no authenticate", 7432, []string{lo}, nil},
		{"port zero", 0, []string{lo}, allowAll},
		{"no interfaces", 7432, nil, allowAll},
	} {
		if tr, err := Open(c.port, c.ifaces, c.auth); err == nil {
			tr.Close()
			t.Errorf("%s: Open succeeded, want an error", c.name)
		}
	}
}

// TestRefreshAfterCloseBindsNothing: a pass that runs after Close opens no
// socket, and Serve after Close refuses.
func TestRefreshAfterCloseBindsNothing(t *testing.T) {
	lo, idx := realIndex(t, "127.0.0.1")
	f := installFakeNet(t)
	f.set(lo, idx, "127.0.0.1")
	tr, err := Open(freePort(t), []string{lo}, allowAll)
	if err != nil {
		t.Fatal(err)
	}
	tr.Close()
	tr.Refresh()
	tr.reconcile()
	if n := len(tr.boundAddrs()); n != 0 {
		t.Fatalf("%d sockets after Close and a pass", n)
	}
	if err := tr.Serve(t.Context(), noPacket, echo); !errors.Is(err, errClosed) {
		t.Fatalf("Serve after Close: %v, want errClosed", err)
	}
}
