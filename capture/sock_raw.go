package capture

import "sync"

// SockRaw is a linux M'maped af_packet socket
type SockRaw struct {
	mu          sync.Mutex
	fd          int
	ifindex     int
	snaplen     int
	pollTimeout uintptr
	frame       uint32 // current frame
	buf         []byte // points to the memory space of the ring buffer shared with the kernel.
	loopIndex   int32  // this field must filled to avoid reading packet twice on a loopback device
}
