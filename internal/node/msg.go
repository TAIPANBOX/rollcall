package node

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/roster"
	"github.com/TAIPANBOX/rollcall/internal/sig"
	"github.com/TAIPANBOX/rollcall/internal/wire"
)

// # Messages
//
// Every packet, a UDP datagram or the request frame of a TCP exchange, is
// one wire packet (package wire, at most wire.MaxPacket bytes) whose
// plaintext starts with a message type byte. A heartbeat is the type byte
// followed by member.EncodeHeartbeat's bytes, which carry their own sender,
// counters and signature. Every other type is the type byte followed by an
// envelope:
//
//	offset  size  field
//	     0     1  type
//	     1    16  from, the sender's member ID
//	    17     8  boot sequence number of the sender
//	    25    16  boot ID of the sender
//	    41     8  packet counter of the sender, shared with its heartbeats
//	    49    16  ref: a random request ID; a reply carries its request's
//	    65     n  payload
//	           64 signature
//
// The signature is sig.Sign(key, "message", epoch (4, big endian) || every
// byte before the signature), so it covers the epoch the packet is sealed
// under and the exact bytes sent (security spec 5.1).
//
// The reply to a TCP request is one frame of chunks, each a two-byte big
// endian length and a wire packet sealed under the request's epoch, whose
// plaintext is chunk index (1) | chunk count (1) | data. The data of all
// chunks, in order, is one message of the form above: a reply is signed by
// its sender and checked as any packet is, and its ref must be the request's.
// A reply can be larger than one packet (a roster of 32 members is about
// 58 KB), and a request cannot: the transport authenticates the first frame
// of a connection with wire.Open before it reads any more.
//
// Payloads are JSON decoded with DisallowUnknownFields and a size limit,
// except two binary ones: a roster (binary envelope of roster.Signed, since
// base64 would not fit 64 KiB) and an epoch delivery part.

// msgType is the first byte of every packet's plaintext.
type msgType byte

// The message types. Values are part of the wire format.
const (
	msgHeartbeat  msgType = 1  // UDP: member.Heartbeat
	msgProbeReq   msgType = 2  // TCP request: do you hear this member?
	msgProbeAck   msgType = 3  // its reply: a member.Report
	msgDigestReq  msgType = 4  // TCP request: the heads you hold
	msgHeads      msgType = 5  // its reply
	msgFetch      msgType = 6  // TCP request: entries of one origin
	msgEntries    msgType = 7  // its reply
	msgRoster     msgType = 8  // TCP request for a roster, and its reply
	msgEpoch      msgType = 9  // TCP request: a part of an epoch key delivery; its reply acknowledges it
	msgJoinReq    msgType = 10 // reserved for the join exchange (pairing carries its own format)
	msgJoinResp   msgType = 11 // reserved, as msgJoinReq
	msgCheckpoint msgType = 12 // reserved for v1.1: decoded and ignored
	msgCPSig      msgType = 13 // reserved for v1.1: decoded and ignored
	msgObjection  msgType = 14 // reserved for v1.1: decoded and ignored
)

// reserved reports whether t is a type v1 checks and then ignores.
func (t msgType) reserved() bool {
	return t == msgCheckpoint || t == msgCPSig || t == msgObjection
}

const (
	// sigKindMessage is the signature kind of every envelope.
	sigKindMessage = "message"
	// envHeader is the envelope's length before the payload.
	envHeader = 1 + 16 + 8 + 16 + 8 + 16
	// envSig is the length of the envelope's signature.
	envSig = ed25519.SignatureSize
	// maxPlain is the largest plaintext of one wire packet.
	maxPlain = wire.MaxPacket - wire.HeaderLen - 16
	// maxRequestPayload is the largest payload a request packet carries.
	maxRequestPayload = maxPlain - envHeader - envSig
	// chunkHeader is the chunk index and count before each chunk's data.
	chunkHeader = 2
	// chunkData is the data one reply chunk carries.
	chunkData = maxPlain - chunkHeader
	// maxFrame is the transport's largest frame.
	maxFrame = 1 << 16
	// maxChunks is the most chunks one reply frame holds.
	maxChunks = maxFrame / (2 + wire.MaxPacket)
	// maxReply is the largest reply message.
	maxReply = maxChunks * chunkData
	// maxReplyPayload is the largest payload of a reply.
	maxReplyPayload = maxReply - envHeader - envSig
	// maxJSON bounds a JSON payload of a request.
	maxJSON = maxRequestPayload
)

var (
	errMalformed = errors.New("node: malformed message")
	errTooLarge  = errors.New("node: message too large")
)

// envelope is one message other than a heartbeat.
type envelope struct {
	typ     msgType
	from    ids.MemberID
	bootSeq uint64
	boot    ids.BootID
	counter uint64
	ref     [16]byte
	payload []byte
	sig     []byte
	raw     []byte // the bytes the signature covers, after the epoch
}

// encodeEnvelope returns e, signed with key for epoch.
func encodeEnvelope(e envelope, epochID uint32, key ed25519.PrivateKey) []byte {
	b := make([]byte, envHeader, envHeader+len(e.payload)+envSig)
	b[0] = byte(e.typ)
	copy(b[1:17], e.from[:])
	binary.BigEndian.PutUint64(b[17:25], e.bootSeq)
	copy(b[25:41], e.boot[:])
	binary.BigEndian.PutUint64(b[41:49], e.counter)
	copy(b[49:65], e.ref[:])
	b = append(b, e.payload...)
	return append(b, sig.Sign(key, sigKindMessage, signedBytes(epochID, b))...)
}

// parseEnvelope reads the fixed fields of b, a message other than a
// heartbeat. It checks lengths only: nothing in it is trusted before Admit
// and the signature.
func parseEnvelope(b []byte) (envelope, bool) {
	if len(b) < envHeader+envSig {
		return envelope{}, false
	}
	var e envelope
	e.typ = msgType(b[0])
	copy(e.from[:], b[1:17])
	e.bootSeq = binary.BigEndian.Uint64(b[17:25])
	copy(e.boot[:], b[25:41])
	e.counter = binary.BigEndian.Uint64(b[41:49])
	copy(e.ref[:], b[49:65])
	end := len(b) - envSig
	e.payload = b[envHeader:end]
	e.sig = b[end:]
	e.raw = b[:end]
	return e, true
}

// signedBytes is what an envelope's signature covers.
func signedBytes(epochID uint32, raw []byte) []byte {
	m := make([]byte, 4, 4+len(raw))
	binary.BigEndian.PutUint32(m, epochID)
	return append(m, raw...)
}

// verify reports whether e is signed by pub for epoch.
func (e envelope) verify(pub ed25519.PublicKey, epochID uint32) bool {
	return sig.Verify(pub, sigKindMessage, signedBytes(epochID, e.raw), e.sig)
}

// sealFrame returns msg as a reply frame of chunks sealed under key for
// epoch.
func sealFrame(key []byte, epochID uint32, msg []byte) ([]byte, error) {
	if len(msg) == 0 || len(msg) > maxReply {
		return nil, errTooLarge
	}
	count := (len(msg) + chunkData - 1) / chunkData
	var out []byte
	for i := 0; i < count; i++ {
		data := msg[i*chunkData : min(len(msg), (i+1)*chunkData)]
		pt := append([]byte{byte(i), byte(count)}, data...)
		p, err := wire.Seal(key, epochID, pt)
		if err != nil {
			return nil, err
		}
		out = binary.BigEndian.AppendUint16(out, uint16(len(p)))
		out = append(out, p...)
	}
	if len(out) > maxFrame {
		return nil, errTooLarge
	}
	return out, nil
}

// openFrame opens a reply frame: every chunk must open under lookup, under
// one epoch, with indexes 0 to count-1 in order and nothing after the last.
func openFrame(lookup wire.KeyLookup, frame []byte) (uint32, []byte, error) {
	if len(frame) == 0 || len(frame) > maxFrame {
		return 0, nil, errMalformed
	}
	var (
		msg   []byte
		epoch uint32
		count = -1
		read  int
	)
	for i := 0; len(frame) > 0; i++ {
		if len(frame) < 2 {
			return 0, nil, errMalformed
		}
		n := int(binary.BigEndian.Uint16(frame))
		if n > len(frame)-2 {
			return 0, nil, errMalformed
		}
		ep, pt, err := wire.Open(lookup, frame[2:2+n])
		if err != nil {
			return 0, nil, err
		}
		frame = frame[2+n:]
		if len(pt) < chunkHeader {
			return 0, nil, errMalformed
		}
		if i == 0 {
			epoch, count = ep, int(pt[1])
			if count < 1 || count > maxChunks {
				return 0, nil, errMalformed
			}
		}
		if ep != epoch || int(pt[0]) != i || int(pt[1]) != count || i >= count {
			return 0, nil, errMalformed
		}
		msg = append(msg, pt[chunkHeader:]...)
		read++
	}
	if count < 0 || read != count || len(msg) == 0 {
		return 0, nil, errMalformed
	}
	return epoch, msg, nil
}

// decodeJSON decodes b, at most max bytes, into v: one JSON value with no
// unknown field and nothing after it.
func decodeJSON(b []byte, v any, max int) error {
	if len(b) > max {
		return errTooLarge
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", errMalformed, err)
	}
	if _, err := d.Token(); err != io.EOF {
		return errMalformed
	}
	return nil
}

// The JSON payloads.
type (
	probeReq struct {
		Target ids.MemberID `json:"target"`
	}
	probeAck struct {
		Target    ids.MemberID `json:"target"`
		Heartbeat []byte       `json:"heartbeat"`
		Ago       int64        `json:"ago"`
		BootSeq   uint64       `json:"boot_seq"`
		Boot      ids.BootID   `json:"boot"`
	}
	digestReq struct{}
	headMsg   struct {
		Origin ids.MemberID `json:"origin"`
		Seq    uint64       `json:"seq"`
		Hash   ids.Hash     `json:"hash"`
		Pruned uint64       `json:"pruned"`
	}
	headsMsg struct {
		Heads []headMsg `json:"heads"`
	}
	fetchReq struct {
		Origin ids.MemberID `json:"origin"`
		From   uint64       `json:"from"`
		To     uint64       `json:"to"`
	}
	entriesMsg struct {
		Entries []history.Entry `json:"entries"`
	}
	rosterReq struct {
		Version uint64 `json:"version"` // 0 for the tip
	}
)

// encodeSigned returns s in the binary envelope: signer (16) | recovery (1)
// | signature (64) | body.
func encodeSigned(s roster.Signed) []byte {
	b := make([]byte, 0, 16+1+ed25519.SignatureSize+len(s.Body))
	b = append(b, s.SignerID[:]...)
	if s.Recovery {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	b = append(b, s.Sig...)
	return append(b, s.Body...)
}

// decodeSigned reads a binary envelope that encodeSigned wrote. It checks
// the layout only; Verify judges the roster.
func decodeSigned(b []byte) (roster.Signed, error) {
	const fixed = 16 + 1 + ed25519.SignatureSize
	if len(b) <= fixed || len(b)-fixed > roster.MaxBodySize || b[16] > 1 {
		return roster.Signed{}, errMalformed
	}
	var s roster.Signed
	copy(s.SignerID[:], b[:16])
	s.Recovery = b[16] == 1
	s.Sig = bytes.Clone(b[17:fixed])
	s.Body = bytes.Clone(b[fixed:])
	return s, nil
}

// rosterReply is the payload of a roster reply: the version the sender
// says it is (a hint for the next request; Verify decides) and the roster.
func encodeRosterReply(version uint64, s roster.Signed) []byte {
	return append(binary.BigEndian.AppendUint64(nil, version), encodeSigned(s)...)
}

func decodeRosterReply(b []byte) (uint64, roster.Signed, error) {
	if len(b) < 8 {
		return 0, roster.Signed{}, errMalformed
	}
	s, err := decodeSigned(b[8:])
	return binary.BigEndian.Uint64(b), s, err
}

// An epoch delivery (epoch.BlobSize bytes) does not fit one request
// packet, so it travels in parts: part (1) | parts (1) | epoch ID (4) |
// data. The reply payload is one byte, an epochAck.
const deliveryParts = 2

type epochAck byte

const (
	ackPart      epochAck = 1 // the part is held, the next one is awaited
	ackInstalled epochAck = 2 // the key is installed
	ackHeld      epochAck = 3 // the member already holds this epoch or a newer one
)

func encodePart(part, parts int, epochID uint32, data []byte) []byte {
	b := []byte{byte(part), byte(parts)}
	b = binary.BigEndian.AppendUint32(b, epochID)
	return append(b, data...)
}

func decodePart(b []byte) (part, parts int, epochID uint32, data []byte, err error) {
	if len(b) < 7 || b[1] != deliveryParts || int(b[0]) >= deliveryParts {
		return 0, 0, 0, nil, errMalformed
	}
	return int(b[0]), int(b[1]), binary.BigEndian.Uint32(b[2:6]), b[6:], nil
}

// The store files of a roster chain: version (1) = 1 | count (1) | for
// each roster, oldest first: length (4, big endian) | binary envelope.
func encodeChain(chain []roster.Signed) []byte {
	b := []byte{1, byte(len(chain))}
	for _, s := range chain {
		e := encodeSigned(s)
		b = binary.BigEndian.AppendUint32(b, uint32(len(e)))
		b = append(b, e...)
	}
	return b
}

func decodeChain(b []byte) ([]roster.Signed, error) {
	if len(b) < 2 || b[0] != 1 || b[1] == 0 {
		return nil, errMalformed
	}
	count := int(b[1])
	b = b[2:]
	var out []roster.Signed
	for i := 0; i < count; i++ {
		if len(b) < 4 {
			return nil, errMalformed
		}
		n := binary.BigEndian.Uint32(b)
		if uint64(n) > uint64(len(b)-4) {
			return nil, errMalformed
		}
		s, err := decodeSigned(b[4 : 4+n])
		if err != nil {
			return nil, err
		}
		out = append(out, s)
		b = b[4+n:]
	}
	if len(b) != 0 {
		return nil, errMalformed
	}
	return out, nil
}
