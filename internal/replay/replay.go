// Package replay rejects replayed packets (security spec 5.3). A Window
// holds, for one peer, the highest boot sequence number seen, the boot ID of
// that boot, and a sliding window of the last WindowSize packet counters.
//
// A packet from an older boot sequence number is rejected. A packet with the
// current boot sequence number but another boot ID is rejected too: a router
// gets a new boot sequence number on every boot, so two boot IDs under one
// number mean a cloned identity or a forgery. Within the current boot, a
// counter seen before, or more than WindowSize-1 below the highest counter
// seen, is rejected. A higher boot sequence number starts a fresh window.
// Wall-clock time plays no part.
//
// A Window lives in memory only and starts empty, and an empty Window
// accepts whatever packet comes first. So after the receiver restarts, the
// first packet from each peer passes on the AEAD alone, even one captured
// from an older boot of that peer.
package replay

import (
	"sync"

	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// WindowSize is the number of counters, the highest included, that a Window
// remembers within one boot.
const WindowSize = 64

// Window is the replay state for one peer. The zero value is an empty
// window, ready to use. A Window is safe for concurrent use; it must not be
// copied after first use, since a copy would accept the same packet again.
type Window struct {
	mu sync.Mutex
	s  state
}

// state is a Window's content. Methods on state never modify it in place.
type state struct {
	seen    bool       // a packet has been accepted
	bootSeq uint64     // the highest boot sequence number accepted
	boot    ids.BootID // the boot ID that came with bootSeq
	highest uint64     // the highest counter accepted in this boot
	bitmap  uint64     // bit i set: counter highest-i was accepted
}

// Accept reports whether a packet with these numbers is fresh and, if it is,
// records it, so the same numbers are rejected from then on. A rejected
// packet changes nothing.
//
// Accept trusts the numbers it is given, so a packet that is accepted must
// be one the receiver believes: call Accept after the AEAD and, for signed
// message types, after the signature has been verified, or a forged packet
// could move the window. Check is the cheap test to run before.
func (w *Window) Accept(bootSeq uint64, boot ids.BootID, counter uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	next, ok := w.s.admit(bootSeq, boot, counter)
	if ok {
		w.s = next
	}
	return ok
}

// Check reports whether Accept would accept a packet with these numbers
// now, and records nothing. It lets a receiver drop a replay before it spends
// time on the signature, at the replay step of the check order (security
// spec 5.2), and record the packet with Accept once the signature is good.
func (w *Window) Check(bootSeq uint64, boot ids.BootID, counter uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, ok := w.s.admit(bootSeq, boot, counter)
	return ok
}

// admit returns the state after accepting the packet and true, or the zero
// state and false if the packet must be rejected; the caller keeps s then.
func (s state) admit(bootSeq uint64, boot ids.BootID, counter uint64) (state, bool) {
	if !s.seen || bootSeq > s.bootSeq {
		return state{seen: true, bootSeq: bootSeq, boot: boot, highest: counter, bitmap: 1}, true
	}
	if bootSeq < s.bootSeq || boot != s.boot {
		return state{}, false
	}
	if counter > s.highest {
		// In Go a shift by 64 or more gives 0, which forgets every counter
		// that fell out of the window.
		s.bitmap = s.bitmap<<(counter-s.highest) | 1
		s.highest = counter
		return s, true
	}
	behind := s.highest - counter
	if behind >= WindowSize || s.bitmap&(uint64(1)<<behind) != 0 {
		return state{}, false
	}
	s.bitmap |= uint64(1) << behind
	return s, true
}
