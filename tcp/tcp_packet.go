package tcp

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

/*
Packet represent data and layers of packet.
parser extracts information from pcap Packet. functions of *Packet doesn't validate if packet is nil,
calllers must make sure that ParsePacket has'nt returned any error before calling any other
function.
*/
type Packet struct {
	// Link layer
	gopacket.LinkLayer

	// IP Header
	gopacket.NetworkLayer
	Version uint8 // Ip version

	// TCP Segment Header
	*layers.TCP

	// Data info
	Lost      uint16
	Timestamp time.Time
}

// ParsePacket parse raw packets
func ParsePacket(packet gopacket.Packet) (pckt *Packet, err error) {
	// early check of error
	_ = packet.ApplicationLayer()
	if e, ok := packet.ErrorLayer().(*gopacket.DecodeFailure); ok {
		err = e.Error()
		return
	}

	// initialization
	pckt = new(Packet)
	pckt.Timestamp = packet.Metadata().Timestamp
	if pckt.Timestamp.IsZero() {
		pckt.Timestamp = time.Now()
	}

	// parsing link layer
	pckt.LinkLayer = packet.LinkLayer()

	// parsing network layer
	if net4, ok := packet.NetworkLayer().(*layers.IPv4); ok {
		pckt.NetworkLayer = net4
		pckt.Version = 4
	} else if net6, ok := packet.NetworkLayer().(*layers.IPv6); ok {
		pckt.NetworkLayer = net6
		pckt.Version = 6
	} else {
		pckt = nil
		return
	}

	// parsing tcp header(transportation layer)
	if tcp, ok := packet.TransportLayer().(*layers.TCP); ok {
		pckt.TCP = tcp
	} else {
		pckt = nil
		return
	}
	pckt.DataOffset *= 4

	// calculating lost data
	headerSize := int(uint32(pckt.DataOffset) + uint32(pckt.IHL()))
	if pckt.Version == 6 {
		headerSize -= 40 // in ipv6 the length of payload doesn't include the IPheader size
	}
	pckt.Lost = pckt.Length() - uint16(headerSize+len(pckt.Payload))

	return
}

// Src returns the source socket of a packet
func (pckt *Packet) Src() string {
	return fmt.Sprintf("%s:%d", pckt.SrcIP(), pckt.SrcPort)
}

// Dst returns destination socket
func (pckt *Packet) Dst() string {
	return fmt.Sprintf("%s:%d", pckt.DstIP(), pckt.DstPort)
}

// SrcIP returns source IP address
func (pckt *Packet) SrcIP() net.IP {
	if pckt.Version == 4 {
		return pckt.NetworkLayer.(*layers.IPv4).SrcIP
	}
	return pckt.NetworkLayer.(*layers.IPv6).SrcIP
}

// DstIP returns destination IP address
func (pckt *Packet) DstIP() net.IP {
	if pckt.Version == 4 {
		return pckt.NetworkLayer.(*layers.IPv4).DstIP
	}
	return pckt.NetworkLayer.(*layers.IPv6).DstIP
}

// IHL returns IP header length in bytes
func (pckt *Packet) IHL() uint8 {
	if l, ok := pckt.NetworkLayer.(*layers.IPv4); ok {
		return l.IHL * 4
	}
	// on IPV6 it's constant, https://en.wikipedia.org/wiki/IPv6_packet#Fixed_header
	return 40
}

// Length returns the total length of the packet(IP header, TCP header and the actual data)
func (pckt *Packet) Length() uint16 {
	if l, ok := pckt.NetworkLayer.(*layers.IPv4); ok {
		return l.Length
	}
	return pckt.NetworkLayer.(*layers.IPv6).Length
}

// SYNOptions returns MSS and windowscale of syn packets
func (pckt *Packet) SYNOptions() (mss uint16, windowscale byte) {
	if !pckt.SYN {
		return
	}
	for _, v := range pckt.Options {
		if v.OptionType == layers.TCPOptionKindMSS {
			mss = binary.BigEndian.Uint16(v.OptionData)
			continue
		}
		if v.OptionType == layers.TCPOptionKindWindowScale {
			if v.OptionLength > 0 {
				windowscale = v.OptionData[0]
			}
		}
	}
	return
}

// Flag returns formatted tcp flags
func (pckt *Packet) Flag() (flag string) {
	if pckt.FIN {
		flag += "FIN, "
	}
	if pckt.SYN {
		flag += "SYN, "
	}
	if pckt.RST {
		flag += "RST, "
	}
	if pckt.PSH {
		flag += "PSH, "
	}
	if pckt.ACK {
		flag += "ACK, "
	}
	if pckt.URG {
		flag += "URG, "
	}
	if len(flag) != 0 {
		return flag[:len(flag)-2]
	}
	return flag
}

// String output for a TCP Packet
func (pckt *Packet) String() string {
	return fmt.Sprintf(`Time: %s
Source: %s
Destination: %s
IHL: %d
Total Length: %d
Sequence: %d
Acknowledgment: %d
DataOffset: %d
Window: %d
Flag: %s
Options: %s
Data Size: %d
Lost Data: %d`,
		pckt.Timestamp.Format(time.StampNano),
		pckt.Src(),
		pckt.Dst(),
		pckt.IHL(),
		pckt.Length(),
		pckt.Seq,
		pckt.Ack,
		pckt.DataOffset,
		pckt.Window,
		pckt.Flag(),
		pckt.Options,
		len(pckt.Payload),
		pckt.Lost,
	)
}
