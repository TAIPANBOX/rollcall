// Command replay resends the UDP payloads of one port from a classic pcap capture to a target.
//
//	replay -pcap lan.pcap -to 192.168.1.1:7432 -count 1
//
// It is a lab tool for the hostile-LAN checks in docs/lab/runbook.md. It is test-only: nothing
// under cmd/ or internal/ imports it, and no release target builds it.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
)

// rollcallPort is the UDP port of the group protocol.
const rollcallPort = 7432

func main() {
	pcapPath := flag.String("pcap", "", "classic pcap file to read (tcpdump -w writes it)")
	to := flag.String("to", "", "destination ip:port, for example 192.168.1.1:7432")
	count := flag.Int("count", 0, "send at most this many payloads; 0 sends all")
	flag.Parse()
	if err := run(*pcapPath, *to, *count, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "replay:", err)
		os.Exit(1)
	}
}

// run sends the payloads of the capture at pcapPath to the address to.
func run(pcapPath, to string, count int, out io.Writer) error {
	if pcapPath == "" {
		return errors.New("-pcap is required")
	}
	if count < 0 {
		return fmt.Errorf("-count must be 0 or more, got %d", count)
	}
	ap, err := netip.ParseAddrPort(to)
	if err != nil {
		return fmt.Errorf("-to %q: want an IP address and port such as 192.168.1.1:7432", to)
	}
	if ap.Port() == 0 {
		return errors.New("-to: port 0 is refused")
	}

	f, err := os.Open(pcapPath)
	if err != nil {
		return err
	}
	defer f.Close()
	payloads, err := ReadPayloads(f, rollcallPort, count)
	if err != nil {
		return fmt.Errorf("%s: %w", pcapPath, err)
	}
	if len(payloads) == 0 {
		return fmt.Errorf("%s: no UDP payloads to port %d", pcapPath, rollcallPort)
	}

	conn, err := listenFor(ap)
	if err != nil {
		return err
	}
	defer conn.Close()
	dst := net.UDPAddrFromAddrPort(ap)
	for i, p := range payloads {
		if _, err := conn.WriteTo(p, dst); err != nil {
			return fmt.Errorf("payload %d: %w", i+1, err)
		}
	}
	fmt.Fprintf(out, "replayed %d payloads to %s\n", len(payloads), ap)
	return nil
}

// listenFor opens an unconnected UDP socket of the family that reaches ap. Unconnected, so an
// ICMP port-unreachable from the target does not end the run.
func listenFor(ap netip.AddrPort) (net.PacketConn, error) {
	if ap.Addr().Unmap().Is4() {
		return net.ListenPacket("udp4", "0.0.0.0:0")
	}
	return net.ListenPacket("udp6", "[::]:0")
}
