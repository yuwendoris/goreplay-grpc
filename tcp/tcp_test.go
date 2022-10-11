package tcp

import (
	"bytes"
	"encoding/binary"

	// "runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/buger/goreplay/proto"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func generateHeader(request bool, seq uint32, length uint16) []byte {
	hdr := make([]byte, 4+24+24)
	binary.BigEndian.PutUint32(hdr, uint32(layers.ProtocolFamilyIPv4))

	ip := hdr[4:]
	ip[0] = 4<<4 | 6
	binary.BigEndian.PutUint16(ip[2:4], length+24+24)
	ip[9] = uint8(layers.IPProtocolTCP)
	copy(ip[12:16], []byte{127, 0, 0, 1})
	copy(ip[16:], []byte{127, 0, 0, 1})

	// set tcp header
	tcp := ip[24:]
	tcp[12] = 6 << 4

	if request {
		binary.BigEndian.PutUint16(tcp, 5535)
		binary.BigEndian.PutUint16(tcp[2:], 8000)
	} else {
		binary.BigEndian.PutUint16(tcp, 8000)
		binary.BigEndian.PutUint16(tcp[2:], 5535)
	}
	binary.BigEndian.PutUint32(tcp[4:], seq)
	return hdr
}

func GetPackets(request bool, start uint32, _len int, payload []byte) []*Packet {
	var packets = make([]*Packet, _len)
	var err error
	for i := start; i < start+uint32(_len); i++ {
		d := append(generateHeader(request, i, uint16(len(payload))), payload...)
		ci := &gopacket.CaptureInfo{Length: len(d), CaptureLength: len(d), Timestamp: time.Now()}

		packets[i-start], err = ParsePacket(d, int(layers.LinkTypeLoop), 4, ci, true)
		if request {
			packets[i-start].Direction = DirIncoming
		} else {
			packets[i-start].Direction = DirOutcoming
		}
		if err != nil {
			panic(err)
		}
	}
	return packets
}

func TestRequestResponseMapping(t *testing.T) {
	packets := []*Packet{
		{SrcPort: 60000, DstPort: 80, Ack: 1, Seq: 1, Direction: DirIncoming, Timestamp: time.Unix(1, 0), Payload: []byte("GET / HTTP/1.1\r\n")},
		{SrcPort: 60000, DstPort: 80, Ack: 1, Seq: 17, Direction: DirIncoming, Timestamp: time.Unix(2, 0), Payload: []byte("Host: localhost\r\n\r\n")},

		// Seq of first response packet match Ack of first request packet
		{SrcPort: 80, DstPort: 60000, Ack: 36, Seq: 1, Direction: DirOutcoming, Timestamp: time.Unix(3, 0), Payload: []byte("HTTP/1.1 200 OK\r\n")},
		{SrcPort: 80, DstPort: 60000, Ack: 36, Seq: 18, Direction: DirOutcoming, Timestamp: time.Unix(4, 0), Payload: []byte("Content-Length: 0\r\n\r\n")},

		// Same TCP stream
		{SrcPort: 60000, DstPort: 80, Ack: 39, Seq: 36, Direction: DirIncoming, Timestamp: time.Unix(5, 0), Payload: []byte("GET / HTTP/1.1\r\n")},
		{SrcPort: 60000, DstPort: 80, Ack: 39, Seq: 52, Direction: DirIncoming, Timestamp: time.Unix(6, 0), Payload: []byte("Host: localhost\r\n\r\n")},

		// Seq of first response packet match Ack of first request packet
		{SrcPort: 80, DstPort: 60000, Ack: 71, Seq: 39, Direction: DirOutcoming, Timestamp: time.Unix(7, 0), Payload: []byte("HTTP/1.1 200 OK\r\n")},
		{SrcPort: 80, DstPort: 60000, Ack: 71, Seq: 56, Direction: DirOutcoming, Timestamp: time.Unix(8, 0), Payload: []byte("Content-Length: 0\r\n\r\n")},
	}

	parser := NewMessageParser(nil, nil, nil, time.Second, false, ProtocolHTTP)
	parser.Start = func(pckt *Packet) (bool, bool) {
		return proto.HasRequestTitle(pckt.Payload), proto.HasResponseTitle(pckt.Payload)
	}
	parser.End = func(m *Message) bool {
		return proto.HasFullPayload(m, m.PacketData()...)
	}

	for _, packet := range packets {
		parser.processPacket(packet)
	}

	messages := []*Message{}
	for i := 0; i < 4; i++ {
		m := parser.Read()
		messages = append(messages, m)
	}

	assert.Equal(t, int(messages[0].Direction), int(DirIncoming))
	assert.Equal(t, int(messages[1].Direction), int(DirOutcoming))
	assert.Equal(t, int(messages[2].Direction), int(DirIncoming))
	assert.Equal(t, int(messages[3].Direction), int(DirOutcoming))

	assert.Equal(t, messages[0].UUID(), messages[1].UUID())
	assert.Equal(t, messages[2].UUID(), messages[3].UUID())

	assert.NotEqual(t, messages[0].UUID(), messages[2].UUID())
}

func TestMessageParserWithHint(t *testing.T) {
	parser := NewMessageParser(nil, nil, nil, time.Second, false, ProtocolHTTP)
	parser.Start = func(pckt *Packet) (bool, bool) {
		return proto.HasRequestTitle(pckt.Payload), proto.HasResponseTitle(pckt.Payload)
	}
	parser.End = func(m *Message) bool {
		return proto.HasFullPayload(m, m.PacketData()...)
	}

	packets := []*Packet{
		// Seq of first response packet match Ack of first request packet
		{SrcPort: 80, DstPort: 60000, Ack: 1, Seq: 1, Direction: DirOutcoming, Timestamp: time.Unix(1, 0), Payload: []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n7\r\n")},
		{SrcPort: 80, DstPort: 60000, Ack: 1, Seq: 18, Direction: DirOutcoming, Timestamp: time.Unix(2, 0), Payload: []byte("\r\nMozilla\r\n9\r\nDeveloper\r")},
		{SrcPort: 80, DstPort: 60000, Ack: 1, Seq: 42, Direction: DirOutcoming, Timestamp: time.Unix(3, 0), Payload: []byte("\n7\r\nNetwork\r\n0\r\n\r\n")},

		{SrcPort: 60000, DstPort: 80, Ack: 60, Seq: 1, Direction: DirIncoming, Timestamp: time.Unix(4, 0), Payload: []byte("POST / HTTP/1.1\r\nContent-Type: text/plain\r\nContent-Length: 23\r\n\r\n")},
		{SrcPort: 60000, DstPort: 80, Ack: 60, Seq: 66, Direction: DirIncoming, Timestamp: time.Unix(5, 0), Payload: []byte("MozillaDeveloper")},
		{SrcPort: 60000, DstPort: 80, Ack: 60, Seq: 82, Direction: DirIncoming, Timestamp: time.Unix(6, 0), Payload: []byte("Network")},

		{SrcPort: 80, DstPort: 60000, Ack: 89, Seq: 1, Direction: DirOutcoming, Timestamp: time.Unix(7, 0), Payload: []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\n")},
	}

	for _, p := range packets {
		parser.processPacket(p)
	}

	messages := []*Message{}
	for i := 0; i < 3; i++ {
		m := parser.Read()
		messages = append(messages, m)
	}

	if !bytes.HasSuffix(messages[0].Data(), []byte("\n7\r\nNetwork\r\n0\r\n\r\n")) {
		t.Errorf("expected to %q to have suffix %q", messages[0].Data(), []byte("\n7\r\nNetwork\r\n0\r\n\r\n"))
	}

	if !bytes.HasSuffix(messages[1].Data(), []byte("Network")) {
		t.Errorf("expected to %q to have suffix %q", messages[1].Data(), []byte("Network"))
	}

	if !bytes.HasSuffix(messages[2].Data(), []byte("Content-Length: 0\r\n\r\n")) {
		t.Errorf("expected to %q to have suffix %q", messages[2].Data(), []byte("Content-Length: 0\r\n\r\n"))
	}
}

func TestMessageParserWrongOrder(t *testing.T) {
	parser := NewMessageParser(nil, nil, nil, time.Second, false, ProtocolHTTP)
	parser.Start = func(pckt *Packet) (bool, bool) {
		return proto.HasRequestTitle(pckt.Payload), proto.HasResponseTitle(pckt.Payload)
	}
	parser.End = func(m *Message) bool {
		return proto.HasFullPayload(m, m.PacketData()...)
	}
	packets := []*Packet{
		// Seq of first response packet match Ack of first request packet
		{SrcPort: 60000, DstPort: 80, Ack: 60, Seq: 66, Direction: DirIncoming, Timestamp: time.Unix(5, 0), Payload: []byte("MozillaDeveloper")},
		{SrcPort: 80, DstPort: 60000, Ack: 1, Seq: 1, Direction: DirOutcoming, Timestamp: time.Unix(1, 0), Payload: []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n7\r\n")},
		{SrcPort: 80, DstPort: 60000, Ack: 1, Seq: 42, Direction: DirOutcoming, Timestamp: time.Unix(3, 0), Payload: []byte("\n7\r\nNetwork\r\n0\r\n\r\n")},

		{SrcPort: 60000, DstPort: 80, Ack: 60, Seq: 1, Direction: DirIncoming, Timestamp: time.Unix(4, 0), Payload: []byte("POST / HTTP/1.1\r\nContent-Type: text/plain\r\nContent-Length: 23\r\n\r\n")},
		{SrcPort: 80, DstPort: 60000, Ack: 1, Seq: 18, Direction: DirOutcoming, Timestamp: time.Unix(2, 0), Payload: []byte("\r\nMozilla\r\n9\r\nDeveloper\r")},

		{SrcPort: 80, DstPort: 60000, Ack: 89, Seq: 1, Direction: DirOutcoming, Timestamp: time.Unix(7, 0), Payload: []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\n")},
		{SrcPort: 60000, DstPort: 80, Ack: 60, Seq: 82, Direction: DirIncoming, Timestamp: time.Unix(6, 0), Payload: []byte("Network")},
	}

	for _, p := range packets {
		parser.processPacket(p)
	}

	m := parser.Read()

	if !bytes.HasSuffix(m.Data(), []byte("\n7\r\nNetwork\r\n0\r\n\r\n")) {
		t.Errorf("expected to %q to have suffix %q", m.Data(), []byte("\n7\r\nNetwork\r\n0\r\n\r\n"))
	}

	m = parser.Read()

	if !bytes.HasSuffix(m.Data(), []byte("Content-Length: 0\r\n\r\n")) {
		t.Errorf("expected to %q to have suffix %q", m.Data(), []byte("Content-Length: 0\r\n\r\n"))
	}

	m = parser.Read()

	if !bytes.HasSuffix(m.Data(), []byte("Network")) {
		t.Errorf("expected to %q to have suffix %q", m.Data(), []byte("Network"))
	}
}

func TestMessageParserWithoutHint(t *testing.T) {
	var data [63 << 10]byte
	packets := GetPackets(true, 1, 10, data[:])

	p := NewMessageParser(nil, nil, nil, time.Second, false, ProtocolHTTP)
	for _, v := range packets {
		p.processPacket(v)
	}
	m := p.Read()

	if m.Length != 63<<10*10 {
		t.Errorf("expected %d to equal %d", m.Length, 63<<10*10)
	}
}

func TestMessageTimeoutReached(t *testing.T) {
	const size = 63 << 11
	var data [size >> 1]byte
	packets := GetPackets(true, 1, 2, data[:])
	p := NewMessageParser(nil, nil, nil, 10*time.Millisecond, true, ProtocolHTTP)
	p.processPacket(packets[0])

	time.Sleep(time.Second * 2)

	p.processPacket(packets[1])
	m := p.Read()
	if m.Length != size {
		t.Errorf("expected %d to equal %d", m.Length, size)
	}
	if !m.TimedOut {
		t.Error("expected message to be timeout")
	}
}

func BenchmarkMessageUUID(b *testing.B) {
	packets := GetPackets(true, 1, 5, nil)

	var uuid []byte
	parser := NewMessageParser(nil, nil, nil, 10*time.Millisecond, true, ProtocolHTTP)
	for _, p := range packets {
		parser.processPacket(p)
	}

	msg := parser.Read()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		uuid = msg.UUID()
	}
	_ = uuid
}

func BenchmarkPacketParseAndSort(b *testing.B) {
	m := new(Message)
	m.packets = make([]*Packet, 100)
	for i, v := range GetPackets(true, 1, 100, nil) {
		m.packets[i] = v
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Sort()
	}
}

func BenchmarkMessageParserWithoutHint(b *testing.B) {
	var chunk = []byte("111111111111111111111111111111")
	packets := GetPackets(true, 1, 1000, chunk)
	p := NewMessageParser(nil, nil, nil, 2*time.Second, false, ProtocolHTTP)
	b.ResetTimer()
	b.ReportMetric(float64(1000), "packets/op")
	for i := 0; i < b.N; i++ {
		for _, v := range packets {
			p.processPacket(v)
		}
		p.Read()
	}
}

func BenchmarkMessageParserWithHint(b *testing.B) {
	var buf [1002][]byte
	var chunk = []byte("1e\r\n111111111111111111111111111111\r\n")
	buf[0] = []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n")
	for i := 1; i < 1000; i++ {
		buf[i] = chunk
	}
	buf[1001] = []byte("0\r\n\r\n")
	packets := make([]*Packet, len(buf))
	for i := 0; i < len(buf); i++ {
		packets[i] = GetPackets(false, 1, 1, buf[i])[0]
	}

	parser := NewMessageParser(nil, nil, nil, 2*time.Second, false, ProtocolHTTP)
	parser.Start = func(pckt *Packet) (bool, bool) {
		return false, proto.HasResponseTitle(pckt.Payload)
	}
	parser.End = func(m *Message) bool {
		return proto.HasFullPayload(m, m.PacketData()...)
	}
	b.ResetTimer()
	b.ReportMetric(float64(len(packets)), "packets/op")
	b.ReportMetric(float64(1000), "chunks/op")
	for i := 0; i < b.N; i++ {
		for j := range packets {
			parser.processPacket(packets[j])
		}
		parser.Read()
	}
}

func BenchmarkNewAndParsePacket(b *testing.B) {
	data := append(generateHeader(true, 1024, 10), make([]byte, 10)...)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParsePacket(data, int(layers.LinkTypeLoop), 4, &gopacket.CaptureInfo{}, true)
	}
}
