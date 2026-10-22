//go:build linux

package control

import (
	"net"
	"syscall"
)

// peerCred reads the peer's uid with SO_PEERCRED: the credentials the
// kernel recorded when the peer connected, not anything the peer sent.
func peerCred(c *net.UnixConn) (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return noUID, err
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return noUID, err
	}
	if credErr != nil {
		return noUID, credErr
	}
	return cred.Uid, nil
}
