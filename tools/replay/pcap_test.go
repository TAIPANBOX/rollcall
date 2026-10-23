package main

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// The capture is built here, so each test shows exactly what the file contains.

var be = binary.BigEndian

// Link types used by the fixtures: Ethernet, raw IP (Linux and BSD numbering).
const (
	fixEthernet = 1
	fixRaw      = 101
	fixRawBSD   = 12
)

// buildPcap writes a classic pcap file. order sets the byte order of the file's own fields;
// magic is the value written first (0xa1b2c3d4 for microseconds, 0xa1b23c4d for nanoseconds).
func buildPcap(order binary.ByteOrder, magic, link uint32, frames ...[]byte) []byte {
	var b bytes.Buffer
	hdr := make([]byte, 24)
	order.PutUint32(hdr[0:], magic)
	order.PutUint16(hdr[4:], 2)
	order.PutUint16(hdr[6:], 4)
	order.PutUint32(hdr[16:], 262144)
	order.PutUint32(hdr[20:], link)
	b.Write(hdr)
	for i, f := range frames {
		rec := make([]byte, 16)
		order.PutUint32(rec[0:], uint32(1700000000+i))
		order.PutUint32(rec[8:], uint32(len(f)))
		order.PutUint32(rec[12:], uint32(len(f)))
		b.Write(rec)
		b.Write(f)
	}
	return b.Bytes()
}

// classic is a little-endian microsecond file.
func classic(link uint32, frames ...[]byte) []byte {
	return buildPcap(binary.LittleEndian, 0xa1b2c3d4, link, frames...)
}

// udpSegment is an 8-byte UDP header followed by payload, with an honest length field.
func udpSegment(dst uint16, payload []byte) []byte {
	u := make([]byte, 8+len(payload))
	be.PutUint16(u[0:], 40000)
	be.PutUint16(u[2:], dst)
	be.PutUint16(u[4:], uint16(len(u)))
	copy(u[8:], payload)
	return u
}

// ipv4 wraps seg in a 20-byte IPv4 header with the given protocol number.
func ipv4(proto byte, seg []byte) []byte {
	ip := make([]byte, 20+len(seg))
	ip[0] = 0x45
	be.PutUint16(ip[2:], uint16(len(ip)))
	ip[8] = 64
	ip[9] = proto
	copy(ip[12:16], []byte{192, 168, 1, 10})
	copy(ip[16:20], []byte{192, 168, 1, 1})
	copy(ip[20:], seg)
	return ip
}

// ipv4UDP is a UDP datagram from 192.168.1.10 to 192.168.1.1, port dst.
func ipv4UDP(dst uint16, payload []byte) []byte {
	return ipv4(17, udpSegment(dst, payload))
}

// ipv6UDP is the same datagram over IPv6, with no extension headers.
func ipv6UDP(dst uint16, payload []byte) []byte {
	seg := udpSegment(dst, payload)
	ip := make([]byte, 40+len(seg))
	ip[0] = 0x60
	be.PutUint16(ip[4:], uint16(len(seg)))
	ip[6] = 17
	ip[7] = 64
	ip[8], ip[9], ip[23] = 0xfe, 0x80, 1   // source fe80::1
	ip[24], ip[25], ip[39] = 0xfe, 0x80, 2 // destination fe80::2
	copy(ip[40:], seg)
	return ip
}

// ethernet wraps body in an Ethernet II header with the given EtherType.
func ethernet(etherType uint16, body []byte) []byte {
	f := make([]byte, 14, 14+len(body))
	be.PutUint16(f[12:], etherType)
	return append(f, body...)
}

// vlan wraps body in an 802.1Q tagged Ethernet header; inner is the EtherType after the tag.
func vlan(tci, inner uint16, body []byte) []byte {
	f := make([]byte, 18, 18+len(body))
	be.PutUint16(f[12:], 0x8100)
	be.PutUint16(f[14:], tci)
	be.PutUint16(f[16:], inner)
	return append(f, body...)
}

func wantPayloads(t *testing.T, got [][]byte, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d payloads %q, want %d %q", len(got), got, len(want), want)
	}
	for i := range want {
		if string(got[i]) != want[i] {
			t.Errorf("payload %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestReadPayloadsEthernetIPv4(t *testing.T) {
	capture := classic(fixEthernet,
		ethernet(0x0800, ipv4UDP(7432, []byte("one"))),
		ethernet(0x0800, ipv4UDP(53, []byte("dns"))),
		ethernet(0x0800, ipv4UDP(7432, []byte("two"))),
	)
	got, err := ReadPayloads(bytes.NewReader(capture), rollcallPort, 0)
	if err != nil {
		t.Fatal(err)
	}
	wantPayloads(t, got, "one", "two")
}

func TestReadPayloadsLimit(t *testing.T) {
	capture := classic(fixEthernet,
		ethernet(0x0800, ipv4UDP(7432, []byte("one"))),
		ethernet(0x0800, ipv4UDP(7432, []byte("two"))),
	)
	got, err := ReadPayloads(bytes.NewReader(capture), rollcallPort, 1)
	if err != nil {
		t.Fatal(err)
	}
	wantPayloads(t, got, "one")
}

func TestReadPayloadsVLANAndIPv6(t *testing.T) {
	capture := classic(fixEthernet,
		vlan(0x0064, 0x0800, ipv4UDP(7432, []byte("tagged"))),
		ethernet(0x86dd, ipv6UDP(7432, []byte("v6"))),
	)
	got, err := ReadPayloads(bytes.NewReader(capture), rollcallPort, 0)
	if err != nil {
		t.Fatal(err)
	}
	wantPayloads(t, got, "tagged", "v6")
}

func TestReadPayloadsRawIP(t *testing.T) {
	for _, link := range []uint32{fixRaw, fixRawBSD} {
		capture := classic(link, ipv4UDP(7432, []byte("raw4")), ipv6UDP(7432, []byte("raw6")))
		got, err := ReadPayloads(bytes.NewReader(capture), rollcallPort, 0)
		if err != nil {
			t.Fatalf("link %d: %v", link, err)
		}
		wantPayloads(t, got, "raw4", "raw6")
	}
}

func TestReadPayloadsIPv4Options(t *testing.T) {
	// IHL 6: a 24-byte header with one 4-byte option. The payload must start after the options.
	seg := udpSegment(rollcallPort, []byte("opts"))
	ip := make([]byte, 24+len(seg))
	ip[0] = 0x46
	be.PutUint16(ip[2:], uint16(len(ip)))
	ip[8] = 64
	ip[9] = 17
	ip[20], ip[21], ip[22] = 1, 1, 1
	copy(ip[24:], seg)
	got, err := ReadPayloads(bytes.NewReader(classic(fixEthernet, ethernet(0x0800, ip))), rollcallPort, 0)
	if err != nil {
		t.Fatal(err)
	}
	wantPayloads(t, got, "opts")
}

func TestReadPayloadsByteOrder(t *testing.T) {
	cases := map[string][]byte{
		"big-endian microseconds": buildPcap(binary.BigEndian, 0xa1b2c3d4, fixEthernet,
			ethernet(0x0800, ipv4UDP(7432, []byte("order")))),
		"little-endian nanoseconds": buildPcap(binary.LittleEndian, 0xa1b23c4d, fixEthernet,
			ethernet(0x0800, ipv4UDP(7432, []byte("order")))),
		"big-endian nanoseconds": buildPcap(binary.BigEndian, 0xa1b23c4d, fixEthernet,
			ethernet(0x0800, ipv4UDP(7432, []byte("order")))),
	}
	for name, capture := range cases {
		got, err := ReadPayloads(bytes.NewReader(capture), rollcallPort, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(got) != 1 || string(got[0]) != "order" {
			t.Errorf("%s: got %q, want [order]", name, got)
		}
	}
}

func TestReadPayloadsIgnoresOtherTraffic(t *testing.T) {
	// A non-first fragment whose bytes look like a UDP header to 7432: it must still be skipped,
	// because only the first fragment carries the UDP header.
	nonFirst := ipv4(17, udpSegment(rollcallPort, []byte("fragment tail")))
	nonFirst[6], nonFirst[7] = 0x00, 0x01 // fragment offset 1
	// IPv6 with a TCP next header.
	v6tcp := ipv6UDP(rollcallPort, []byte("tcp"))
	v6tcp[6] = 6
	capture := classic(fixEthernet,
		ethernet(0x0806, make([]byte, 28)),                                 // ARP
		ethernet(0x0800, ipv4(6, udpSegment(rollcallPort, []byte("tcp")))), // TCP to 7432
		ethernet(0x0800, nonFirst),
		ethernet(0x86dd, v6tcp),
		ethernet(0x0800, ipv4UDP(7432, []byte("ok"))),
	)
	got, err := ReadPayloads(bytes.NewReader(capture), rollcallPort, 0)
	if err != nil {
		t.Fatal(err)
	}
	wantPayloads(t, got, "ok")
}

func TestReadPayloadsRejectsCutShortDatagram(t *testing.T) {
	seg := udpSegment(rollcallPort, make([]byte, 12))
	be.PutUint16(seg[4:], 100) // claims 100 bytes, the capture holds 20
	capture := classic(fixEthernet, ethernet(0x0800, ipv4(17, seg)))
	_, err := ReadPayloads(bytes.NewReader(capture), rollcallPort, 0)
	if err == nil || !strings.Contains(err.Error(), "cut short") || !strings.Contains(err.Error(), "frame 1") {
		t.Fatalf("err = %v, want a frame 1 cut-short error", err)
	}
}

func TestReadPayloadsRejectsFirstFragment(t *testing.T) {
	ip := ipv4UDP(rollcallPort, []byte("frag"))
	ip[6] = 0x20 // more fragments follow, offset 0
	_, err := ReadPayloads(bytes.NewReader(classic(fixEthernet, ethernet(0x0800, ip))), rollcallPort, 0)
	if err == nil || !strings.Contains(err.Error(), "fragment") {
		t.Fatalf("err = %v, want a fragment error", err)
	}
}

func TestReadPayloadsBadInput(t *testing.T) {
	valid := classic(fixEthernet, ethernet(0x0800, ipv4UDP(rollcallPort, []byte("x"))))
	tooLarge := buildPcap(binary.LittleEndian, 0xa1b2c3d4, fixEthernet)
	tooLarge = append(tooLarge, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(tooLarge[24+8:], 1<<20)
	cutData := classic(fixEthernet)
	cutData = append(cutData, make([]byte, 16)...)
	binary.LittleEndian.PutUint32(cutData[24+8:], 60) // claims 60 bytes, none follow

	cases := map[string]struct {
		data []byte
		want string
	}{
		"short global header": {[]byte{0xd4, 0xc3}, "global header"},
		"not a pcap":          {bytes.Repeat([]byte("x"), 40), "not a classic pcap"},
		"pcapng":              {append([]byte{0x0a, 0x0d, 0x0d, 0x0a}, make([]byte, 36)...), "pcapng"},
		"unsupported link":    {classic(147), "link type 147"},
		"record header cut":   {valid[:24+10], "record header"},
		"record data cut":     {cutData, "frame 1"},
		"record too large":    {tooLarge, "too large"},
	}
	for name, c := range cases {
		_, err := ReadPayloads(bytes.NewReader(c.data), rollcallPort, 0)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want it to mention %q", name, err, c.want)
		}
	}
}

func TestReadPayloadsEmptyCapture(t *testing.T) {
	got, err := ReadPayloads(bytes.NewReader(classic(fixEthernet)), rollcallPort, 0)
	if err != nil || len(got) != 0 {
		t.Fatalf("got %q, %v; want no payloads and no error", got, err)
	}
}

// FuzzReadPayloads: arbitrary bytes from a capture file never panic.
func FuzzReadPayloads(f *testing.F) {
	f.Add(classic(fixEthernet, ethernet(0x0800, ipv4UDP(rollcallPort, []byte("seed")))))
	f.Add(classic(fixRaw, ipv6UDP(rollcallPort, []byte("seed6"))))
	f.Add(buildPcap(binary.BigEndian, 0xa1b2c3d4, fixEthernet, vlan(1, 0x0800, ipv4UDP(rollcallPort, nil))))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ReadPayloads(bytes.NewReader(data), rollcallPort, 0)
	})
}
