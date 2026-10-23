//go:build linux

package transport

import (
	"errors"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"
	"time"
)

// routeTimeout bounds the wait for the kernel's answer to a route lookup.
const routeTimeout = time.Second

var routeSeq atomic.Uint32

// kernelRoute asks the kernel over rtnetlink how it routes dst, as
// "ip route get" does, and gets the outgoing interface itself (RTA_OIF) with
// the source it prefers (RTA_PREFSRC). It needs no privilege: RTM_GETROUTE is
// a question, and the daemon already speaks NETLINK_ROUTE whenever it lists
// interfaces (net.Interfaces), so the seccomp list allows every call here
// (socket, setsockopt, bind, sendto, recvfrom, close). The answer covers
// policy routing and interfaces without an address of dst's family, which a
// source address alone would not name.
func kernelRoute(dst netip.Addr) (route, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return route{}, os.NewSyscallError("socket", err)
	}
	defer syscall.Close(fd)
	tv := syscall.NsecToTimeval(routeTimeout.Nanoseconds())
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return route{}, os.NewSyscallError("setsockopt", err)
	}
	kernel := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return route{}, os.NewSyscallError("bind", err)
	}
	seq := routeSeq.Add(1)
	if err := syscall.Sendto(fd, routeRequest(seq, dst), 0, kernel); err != nil {
		return route{}, os.NewSyscallError("sendto", err)
	}
	buf := make([]byte, 4096)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return route{}, os.NewSyscallError("recvfrom", err)
		}
		return parseRouteReply(buf[:n], seq)
	}
}
