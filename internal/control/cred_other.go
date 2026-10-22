//go:build !linux

package control

import (
	"errors"
	"net"
	"runtime"
)

// peerCred has no SO_PEERCRED to read outside Linux, so every peer is
// refused there. rollcall runs on OpenWrt; other platforms only build it.
func peerCred(*net.UnixConn) (uint32, error) {
	return noUID, errors.New("control: peer credentials are not supported on " + runtime.GOOS)
}
