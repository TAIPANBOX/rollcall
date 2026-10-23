package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"
)

// Classic libpcap files, as tcpdump -w writes them. pcapng is refused rather than guessed at.
const (
	magicMicro = 0xa1b2c3d4
	magicNano  = 0xa1b23c4d
	magicNG    = 0x0a0d0d0a

	linkEthernet = 1
	linkRaw      = 101
	linkRawBSD   = 12 // DLT_RAW on BSD and macOS

	globalHeaderLen = 24
	recordHeaderLen = 16
	maxRecordLen    = 256 << 10 // far above any frame of the group protocol (1200-byte packets)

	etherIPv4 = 0x0800
	etherVLAN = 0x8100
	etherIPv6 = 0x86dd

	protoUDP     = 17
	udpHeaderLen = 8
)

// ReadPayloads reads a classic pcap stream and returns the UDP payloads sent to dstPort, in
// capture order. limit caps the count; 0 means all.
//
// Frames that are not UDP to dstPort are skipped. IPv6 extension headers are not followed, so a
// UDP datagram behind one is skipped too. A datagram to dstPort that cannot be replayed whole
// (a first IPv4 fragment, or a payload cut short by the capture's snap length) is an error that
// names its frame, so a partial packet is never sent.
func ReadPayloads(r io.Reader, dstPort uint16, limit int) ([][]byte, error) {
	br := bufio.NewReader(r)
	hdr := make([]byte, globalHeaderLen)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return nil, fmt.Errorf("pcap global header: %w", err)
	}
	order, err := fileOrder(hdr[:4])
	if err != nil {
		return nil, err
	}
	link := order.Uint32(hdr[20:24])
	switch link {
	case linkEthernet, linkRaw, linkRawBSD:
	default:
		return nil, fmt.Errorf("unsupported link type %d: capture Ethernet or raw IP", link)
	}

	var payloads [][]byte
	rec := make([]byte, recordHeaderLen)
	for frame := 1; limit <= 0 || len(payloads) < limit; frame++ {
		if _, err := io.ReadFull(br, rec); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("frame %d: record header: %w", frame, err)
		}
		n := order.Uint32(rec[8:12])
		if n > maxRecordLen {
			return nil, fmt.Errorf("frame %d: record of %d bytes is too large", frame, n)
		}
		data := make([]byte, n)
		if _, err := io.ReadFull(br, data); err != nil {
			return nil, fmt.Errorf("frame %d: record cut short: %w", frame, err)
		}
		payload, ok, err := datagram(link, data, dstPort)
		if err != nil {
			return nil, fmt.Errorf("frame %d: %w", frame, err)
		}
		if ok {
			payloads = append(payloads, payload)
		}
	}
	return payloads, nil
}

// fileOrder reads the byte order of the file from its magic number.
func fileOrder(magic []byte) (binary.ByteOrder, error) {
	le := binary.LittleEndian.Uint32(magic)
	switch {
	case le == magicNG:
		return nil, fmt.Errorf("pcapng is not supported: capture with tcpdump -w, which writes classic pcap")
	case le == magicMicro || le == magicNano:
		return binary.LittleEndian, nil
	case bits.ReverseBytes32(le) == magicMicro || bits.ReverseBytes32(le) == magicNano:
		return binary.BigEndian, nil
	}
	return nil, fmt.Errorf("not a classic pcap file (magic %#08x)", le)
}

// datagram returns the UDP payload of one captured frame when the frame is a UDP datagram to
// dstPort. Any other frame is reported as not matching, with no error.
func datagram(link uint32, frame []byte, dstPort uint16) ([]byte, bool, error) {
	if link != linkEthernet {
		if len(frame) == 0 {
			return nil, false, nil
		}
		return udpToPort(frame, frame[0]>>4, dstPort)
	}
	if len(frame) < 14 {
		return nil, false, nil
	}
	etherType := be16(frame[12:14])
	body := frame[14:]
	if etherType == etherVLAN {
		if len(body) < 4 {
			return nil, false, nil
		}
		etherType = be16(body[2:4])
		body = body[4:]
	}
	switch etherType {
	case etherIPv4:
		return udpToPort(body, 4, dstPort)
	case etherIPv6:
		return udpToPort(body, 6, dstPort)
	}
	return nil, false, nil
}

// udpToPort dispatches on the IP version the frame claims to carry.
func udpToPort(pkt []byte, version byte, dstPort uint16) ([]byte, bool, error) {
	switch version {
	case 4:
		return v4Datagram(pkt, dstPort)
	case 6:
		return v6Datagram(pkt, dstPort)
	}
	return nil, false, nil
}

// v4Datagram finds a UDP datagram to dstPort inside an IPv4 packet.
func v4Datagram(pkt []byte, dstPort uint16) ([]byte, bool, error) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return nil, false, nil
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || ihl > len(pkt) || pkt[9] != protoUDP {
		return nil, false, nil
	}
	flags := be16(pkt[6:8])
	if flags&0x1fff != 0 {
		return nil, false, nil // a later fragment carries no UDP header
	}
	return udpPayloadOf(pkt[ihl:], dstPort, flags&0x2000 != 0)
}

// v6Datagram finds a UDP datagram to dstPort inside an IPv6 packet with no extension headers.
func v6Datagram(pkt []byte, dstPort uint16) ([]byte, bool, error) {
	if len(pkt) < 40 || pkt[0]>>4 != 6 || pkt[6] != protoUDP {
		return nil, false, nil
	}
	return udpPayloadOf(pkt[40:], dstPort, false)
}

// udpPayloadOf reads the UDP header at the start of seg. It returns the payload when the
// destination port is dstPort. moreFragments reports an IPv4 first fragment, which cannot be
// replayed whole, so it is an error rather than a skip.
func udpPayloadOf(seg []byte, dstPort uint16, moreFragments bool) ([]byte, bool, error) {
	if len(seg) < udpHeaderLen || be16(seg[2:4]) != dstPort {
		return nil, false, nil
	}
	if moreFragments {
		return nil, false, fmt.Errorf("fragmented datagram to port %d: cannot replay it whole", dstPort)
	}
	n := int(be16(seg[4:6]))
	if n < udpHeaderLen {
		return nil, false, fmt.Errorf("UDP length %d is shorter than its header", n)
	}
	if n > len(seg) {
		return nil, false, fmt.Errorf("UDP payload cut short: the capture holds %d of %d bytes; capture with tcpdump -s 0", len(seg), n)
	}
	return seg[udpHeaderLen:n], true, nil
}

func be16(b []byte) uint16 { return binary.BigEndian.Uint16(b) }
