// +build !linux

package capture

import (
	"errors"
	"net"
)

// NewSockRaw returns new M'maped sock_raw on packet version 2.
func NewSockRaw(_ net.Interface) (*SockRaw, error) {
	return nil, errors.New("afpacket socket is only available on linux")
}
