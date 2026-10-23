// Command flood sends random UDP datagrams to one address on the LAN, for the hostile-LAN checks
// in docs/lab/runbook.md.
//
//	flood -to 192.168.1.1:7432 -n 10000 -size 1200
//
// The target must be loopback, link-local or private (see checkTarget). The tool is test-only:
// nothing under cmd/ or internal/ imports it, and no release target builds it.
package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
)

// maxPayload is the largest UDP payload over IPv4.
const maxPayload = 65507

func main() {
	to := flag.String("to", "", "target ip:port on a loopback, link-local or private address")
	n := flag.Int("n", 10000, "number of datagrams")
	size := flag.Int("size", 1200, "payload bytes per datagram, 1 to 65507")
	flag.Parse()
	if err := run(*to, *n, *size, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "flood:", err)
		os.Exit(1)
	}
}

// run sends n datagrams of size random bytes each to the address to.
func run(to string, n, size int, out io.Writer) error {
	ap, err := checkTarget(to)
	if err != nil {
		return err
	}
	if n < 1 {
		return fmt.Errorf("-n must be at least 1, got %d", n)
	}
	if size < 1 || size > maxPayload {
		return fmt.Errorf("-size must be 1 to %d, got %d", maxPayload, size)
	}

	conn, err := listenFor(ap)
	if err != nil {
		return err
	}
	defer conn.Close()
	dst := net.UDPAddrFromAddrPort(ap)
	buf := make([]byte, size)
	for i := 0; i < n; i++ {
		if _, err := rand.Read(buf); err != nil {
			return err
		}
		if _, err := conn.WriteTo(buf, dst); err != nil {
			return fmt.Errorf("datagram %d: %w", i+1, err)
		}
	}
	fmt.Fprintf(out, "sent %d random datagrams of %d bytes to %s\n", n, size, ap)
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
