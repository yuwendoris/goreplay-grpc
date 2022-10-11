package tcp

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/buger/goreplay/http2_protocol"
	"github.com/buger/goreplay/testg"
	pb "github.com/golang/protobuf/proto"
	"golang.org/x/net/http2"
	"net"
	"reflect"
	"sort"
	"sync"
	"time"
	"unsafe"

	"github.com/buger/goreplay/proto"
)

// TCPProtocol is a number to indicate type of protocol
type TCPProtocol uint8

const (
	// ProtocolHTTP ...
	ProtocolHTTP TCPProtocol = iota
	// ProtocolBinary ...
	ProtocolBinary
	// ProtocolHTTP2 ...
	ProtocolHTTP2
)

// Set is here so that TCPProtocol can implement flag.Var
func (protocol *TCPProtocol) Set(v string) error {
	switch v {
	case "", "http":
		*protocol = ProtocolHTTP
	case "binary":
		*protocol = ProtocolBinary
	case "http2":
		*protocol = ProtocolHTTP2
	default:
		return fmt.Errorf("unsupported protocol %s", v)
	}
	return nil
}

func (protocol *TCPProtocol) String() string {
	switch *protocol {
	case ProtocolBinary:
		return "binary"
	case ProtocolHTTP:
		return "http"
	case ProtocolHTTP2:
		return "http2"
	default:
		return ""
	}
}

// Stats every message carry its own stats object
type Stats struct {
	LostData  int
	Length    int       // length of the data
	Start     time.Time // first packet's timestamp
	End       time.Time // last packet's timestamp
	SrcAddr   string
	DstAddr   string
	Direction Dir
	TimedOut  bool // timeout before getting the whole message
	Truncated bool // last packet truncated due to max message size
	IPversion byte
}

// Message is the representation of a tcp message
type Message struct {
	packets          []*Packet
	parser           *MessageParser
	Stream           *Stream
	feedback         interface{}
	Idx              uint16
	StreamId         uint64 // ip+port+streamId
	ConnId           uint64 // ip+port
	continueAdjusted bool

	Stats
	TransferCompleteChan chan bool
}

// UUID returns the UUID of a TCP request and its response.
func (m *Message) UUID() []byte {
	var streamID uint64
	pckt := m.packets[0]

	// check if response or request have generated the ID before.
	if m.Direction == DirIncoming {
		streamID = uint64(pckt.SrcPort)<<48 | uint64(pckt.DstPort)<<32 |
			uint64(ip2int(pckt.SrcIP))
	} else {
		streamID = uint64(pckt.DstPort)<<48 | uint64(pckt.SrcPort)<<32 |
			uint64(ip2int(pckt.DstIP))
	}

	id := make([]byte, 12)
	binary.BigEndian.PutUint64(id, streamID)

	if m.Direction == DirIncoming {
		binary.BigEndian.PutUint32(id[8:], pckt.Ack)
	} else {
		binary.BigEndian.PutUint32(id[8:], pckt.Seq)
	}

	uuidHex := make([]byte, 24)
	hex.Encode(uuidHex[:], id[:])

	return uuidHex
}

func (m *Message) add(packet *Packet) bool {
	// Skip duplicates
	for _, p := range m.packets {
		if p.Seq == packet.Seq {
			return false
		}
	}

	// Packets not always captured in same Seq order, and sometimes we need to prepend
	if len(m.packets) == 0 || packet.Seq > m.packets[len(m.packets)-1].Seq {
		m.packets = append(m.packets, packet)
	} else if packet.Seq < m.packets[0].Seq {
		m.packets = append([]*Packet{packet}, m.packets...)
	} else { // insert somewhere in the middle...
		for i, p := range m.packets {
			if packet.Seq < p.Seq {
				m.packets = append(m.packets[:i], append([]*Packet{packet}, m.packets[i:]...)...)
				break
			}
		}
	}

	m.Length += len(packet.Payload)
	m.LostData += int(packet.Lost)

	if packet.Timestamp.After(m.End) || m.End.IsZero() {
		m.End = packet.Timestamp
	}

	return true
}

// Packets returns packets of the message
func (m *Message) Packets() []*Packet {
	return m.packets
}

func (m *Message) MissingChunk() bool {
	nextSeq := m.packets[0].Seq

	for _, p := range m.packets {
		if p.Seq != nextSeq {
			return true
		}

		nextSeq += uint32(len(p.Payload))
	}

	return false
}

func (m *Message) PacketData() [][]byte {
	tmp := make([][]byte, len(m.packets))

	for i, p := range m.packets {
		tmp[i] = p.Payload
	}

	return tmp
}

// get complete http2_protocol message
func (m *Message) PacketDataHttp2() []byte {
	req := new(http2_protocol.Request)
	resp := new(http2_protocol.Response)

	fmt.Println("m.Stream  1111", m.Stream, m.packets)
	for _, p := range m.packets {
		for _, frame := range p.PayloadFrame {
			switch targetFrame := frame.(type) {
			case *http2.MetaHeadersFrame:
				// 要进行field插入
				for _, field := range targetFrame.Fields {
					m.Stream.Conn.Enc.WriteField(hpack.HeaderField{Name: field.Name, Value: field.Value})

					if field.Name == ":scheme" {
						req.Header.Scheme = field.Value
					}

					if field.Name == ":path" {
						req.Header.Method = field.Value

						// get input message through request method
						targetPackage, service, method := testg.AnalysisPath(field.Value)
						inputType, outputType := testg.GetRpcInAndOutType(targetPackage, service, method)
						inputTypeName := targetPackage + "." + inputType.GetName()
						pi := testg.GetMessage(inputTypeName)
						inputMessage := reflect.New(pi.Elem()).Interface().(pb.Message)
						m.Stream.GrpcInput = inputMessage

						outputTypeName := targetPackage + "." + outputType.GetName()
						po := testg.GetMessage(outputTypeName)
						outputMessage := reflect.New(po.Elem()).Interface().(pb.Message)
						m.Stream.GrpcOutput = outputMessage
					}
				}
			case *http2.DataFrame:
				if targetFrame.Length == 0 {
					continue
				}
				// judge direction of message
				if m.Stats.Direction == DirIncoming {
					if targetFrame.Data() != nil {
						inputMessage := m.Stream.GrpcInput
						pb.Unmarshal(targetFrame.Data()[5:], inputMessage) // todo grpc compression handle

						req.Data = append(req.Data, inputMessage)
					}
				} else if m.Stats.Direction == DirOutcoming {
					fmt.Println("m.Stream", m.Stream)
					outputMessage := m.Stream.GrpcOutput
					fmt.Println("DirOutcoming", outputMessage, targetFrame.Data()[5:])
					pb.Unmarshal(targetFrame.Data()[5:], outputMessage)

					resp.Data.Data = append(resp.Data.Data, outputMessage)
				}
			}
		}
	}

	if req != nil {
		bytes, err := json.Marshal(req)

		if err != nil {
			fmt.Println(err)
		}

		return bytes
	}

	if resp != nil {
		bytes, err := json.Marshal(resp)
		delete(m.parser.StreamParser.S, m.StreamId)

		if err != nil {
			fmt.Println(err)
		}

		return bytes
	}

	return []byte{}
}

func (m *Message) DataHttp2() []byte {
	return m.PacketDataHttp2()
}

// Data returns data in this message
func (m *Message) Data() []byte {
	packetData := m.PacketData()
	tmp := packetData[0]

	if len(packetData) > 0 {
		tmp, _ = copySlice(tmp, len(packetData[0]), packetData[1:]...)
	}

	// Remove Expect header, since its replay not fully supported
	if state, ok := m.feedback.(*proto.HTTPState); ok {
		if state.Continue100 {
			tmp = proto.DeleteHeader(tmp, []byte("Expect"))
		}
	}

	return tmp
}

// SetProtocolState set feedback/data that can be used later, e.g with End or Start hint
func (m *Message) SetProtocolState(feedback interface{}) {
	m.feedback = feedback
}

// ProtocolState returns feedback associated to this message
func (m *Message) ProtocolState() interface{} {
	return m.feedback
}

// Sort a helper to sort packets
func (m *Message) Sort() {
	sort.SliceStable(m.packets, func(i, j int) bool { return m.packets[i].Seq < m.packets[j].Seq })
}

// Emitter message handler
type Emitter func(*Message)

// HintEnd hints the parser to stop the session, see MessageParser.End
// when set, it will be executed before checking FIN or RST flag
type HintEnd func(*Message) bool

// HintStart hints the parser to start the reassembling the message, see MessageParser.Start
// when set, it will be called after checking SYN flag
type HintStart func(*Packet) (IsRequest, IsOutgoing bool)

// MessageParser holds data of all tcp messages in progress(still receiving/sending packets).
// message is identified by its source port and dst port, and last 4bytes of src IP.
type MessageParser struct {
	m  []map[uint64]*Message
	mL []sync.RWMutex

	messageExpire  time.Duration // the maximum time to wait for the final packet, minimum is 100ms
	allowIncompete bool
	End            HintEnd
	Start          HintStart
	ticker         *time.Ticker
	messages       chan *Message
	packets        chan *PcapPacket
	close          chan struct{} // to signal that we are able to close
	ports          []uint16
	ips            []net.IP
	protocol       TCPProtocol
	StreamParser   *StreamParser
}

// NewMessageParser returns a new instance of message parser
func NewMessageParser(messages chan *Message, ports []uint16, ips []net.IP, messageExpire time.Duration, allowIncompete bool, protocol TCPProtocol) (parser *MessageParser) {
	parser = new(MessageParser)

	parser.messageExpire = messageExpire
	if parser.messageExpire == 0 {
		parser.messageExpire = time.Millisecond * 1000
	}

	parser.allowIncompete = allowIncompete
	parser.protocol = protocol

	parser.packets = make(chan *PcapPacket, 10000)

	if messages == nil {
		messages = make(chan *Message, 100)
	}
	parser.messages = messages
	parser.ticker = time.NewTicker(time.Millisecond * 100)
	parser.close = make(chan struct{}, 1)

	parser.ports = ports
	parser.ips = ips

	for i := 0; i < 10; i++ {
		parser.m = append(parser.m, make(map[uint64]*Message))
		parser.mL = append(parser.mL, sync.RWMutex{})
	}

	for i := 0; i < 10; i++ {
		go parser.wait(i)
	}

	return parser
}

var packetLen int

// Packet returns packet handler
func (parser *MessageParser) PacketHandler(packet *PcapPacket) {
	packetLen++
	parser.packets <- packet
}

func (parser *MessageParser) wait(index int) {
	var (
		now time.Time
	)
	for {
		select {
		case pckt := <-parser.packets:
			parser.processPacket(parser.parsePacket(pckt))
		case now = <-parser.ticker.C:
			fmt.Println(now)
			parser.timer(now, index)
		case <-parser.close:
			parser.ticker.Stop()
			// parser.Close should wait for this function to return
			parser.close <- struct{}{}
			return
		default:
		}
	}
}

func (parser *MessageParser) parsePacket(pcapPkt *PcapPacket) *Packet {
	pckt, err := ParsePacket(pcapPkt.Data, pcapPkt.LType, pcapPkt.LTypeLen, pcapPkt.Ci, false)
	if err != nil {
		if _, empty := err.(EmptyPacket); !empty {
			stats.Add("packet_error", 1)
		}
		return nil
	}

	for _, p := range parser.ports {
		if pckt.DstPort == p {
			for _, ip := range parser.ips {
				if pckt.DstIP.Equal(ip) {
					pckt.Direction = DirIncoming
					break
				}
			}
			break
		}
	}

	if parser.protocol == ProtocolHTTP2 && pckt.FIN && pckt.ACK {
		connId := pckt.ConnId()
		delete(parser.StreamParser.ConnParser.C, connId)

		gg := parser.StreamParser.ConnParser.C[pckt.streamID].ConnStream
		for _, kk := range gg {
			delete(parser.StreamParser.S, kk.Idx)
		}
	}

	return pckt
}

func splitPayloadBytes(payload []byte, frameByteList [][]byte) [][]byte {
	if len(payload) == 0 {
		return frameByteList
	}

	length := (uint32(payload[0])<<16 | uint32(payload[1])<<8 | uint32(payload[2]))

	frameByteList = append(frameByteList, payload[0:length+9])

	return splitPayloadBytes(payload[length+9:], frameByteList)
}

func (parser *MessageParser) getMIDX(pckt *Packet) uint16 {
	mIDX := uint16(0)
	if pckt.Direction == DirUnknown {
		if in, out := parser.Start(pckt); in || out {
			if in {
				pckt.Direction = DirIncoming
			} else {
				pckt.Direction = DirOutcoming
			}
		}
	}

	if pckt.Direction == DirIncoming {
		mIDX = pckt.SrcPort % 10
	} else {
		mIDX = pckt.DstPort % 10
	}

	return mIDX
}

func (parser *MessageParser) processPacket(pckt *Packet) {
	if pckt == nil {
		return
	}

	mID := uint64(0)
	connId := uint64(0)
	mIDX := uint16(0)
	streamId := uint32(0)
	mStreamId := uint64(0)
	if parser.protocol == ProtocolHTTP2 {
		// magic Check
		if http2_protocol.CheckMagic(pckt.Payload) {

			if parser.StreamParser.ConnParser.C[pckt.ConnId()] != nil {
				parser.StreamParser.ConnParser.C[pckt.ConnId()].SetNewCoder()
				delete(parser.StreamParser.ConnParser.C, parser.m[mIDX][pckt.messageID].ConnId)
			}

			return
		}

		frameList := splitPayloadBytes(pckt.Payload, [][]byte{})

		for _, frameByte := range frameList {
			payloadFrame := http2_protocol.TransferFrame(frameByte)
			pckt.PayloadFrame = append(pckt.PayloadFrame, payloadFrame)
			frameType := http2_protocol.GetType(payloadFrame)
			if frameType != "DATA" &&
				frameType != "HEADERS" &&
				frameType != "CONTINUATION" {
				return
			}

			streamId := http2_protocol.GetSteamId(payloadFrame)
			mID = pckt.MessageIDHttp2(streamId)
			connId = pckt.ConnId()
		}
	}

	// Trying to build unique hash, but there is small chance of collision
	// No matter if it is request or response, all packets in the same message have same
	if parser.protocol == ProtocolHTTP {
		mID = pckt.MessageID()
	}
	mIDX = parser.getMIDX(pckt)
	if parser.protocol == ProtocolHTTP2 {
		mStreamId = pckt.StreamId(streamId)
	}
	parser.mL[mIDX].Lock()
	m, ok := parser.m[mIDX][mID]
	if !ok {
		parser.mL[mIDX].Unlock()
	}

	switch {
	case ok:
		parser.addPacket(m, pckt)

		parser.mL[mIDX].Unlock()
		return
	}

	parser.mL[mIDX].Lock()

	m = new(Message)
	m.Direction = pckt.Direction
	m.SrcAddr = pckt.SrcIP.String()
	m.DstAddr = pckt.DstIP.String()
	m.TransferCompleteChan = make(chan bool)

	parser.m[mIDX][mID] = m

	m.Idx = mIDX
	m.ConnId = connId
	m.StreamId = mStreamId
	m.Start = pckt.Timestamp
	m.parser = parser
	parser.addPacket(m, pckt)

	parser.mL[mIDX].Unlock()
}

func (parser *MessageParser) addPacket(m *Message, pckt *Packet) bool {
	if !m.add(pckt) {
		return false
	}

	// If we are using protocol parsing, like HTTP, depend on its parsing func.
	// For the binary procols wait for message to expire
	if parser.End != nil {
		if parser.End(m) {
			parser.Emit(m)
			return true
		}

		parser.Fix100Continue(m)
	}

	return true
}

func (parser *MessageParser) Fix100Continue(m *Message) {
	// Only adjust a message once
	if state, ok := m.feedback.(*proto.HTTPState); ok && state.Continue100 && !m.continueAdjusted {
		delete(parser.m[m.Idx], m.packets[0].MessageID())

		// Shift Ack by given offset
		// Size of "HTTP/1.1 100 Continue\r\n\r\n" message
		for _, p := range m.packets {
			p.messageID = 0
			p.Ack += 25
		}

		// If next section was aready approved and received, merge messages
		if next, found := parser.m[m.Idx][m.packets[0].MessageID()]; found {
			for _, p := range next.packets {
				parser.addPacket(m, p)
			}
		}

		// Re-add (or override) again with new message and ID
		parser.m[m.Idx][m.packets[0].MessageID()] = m
		m.continueAdjusted = true
	}
}

func (parser *MessageParser) Read() *Message {
	m := <-parser.messages
	return m
}

// streamHandler处理
func (parser *MessageParser) Emit(m *Message) {
	stats.Add("message_count", 1)

	if parser.protocol == ProtocolHTTP2 {
		// todo stream handler
		parser.StreamParser.MessageHandler(m)
		delete(parser.m[m.Idx], m.packets[0].MessageIDHttp2(http2_protocol.GetSteamId(m.packets[0].PayloadFrame[0])))
	} else {
		delete(parser.m[m.Idx], m.packets[0].MessageID())
	}

	go parser.waitEmit(m)
}

func (parser *MessageParser) waitEmit(m *Message) {
	for {
		select {

		case <-m.TransferCompleteChan:
			fmt.Println("parser.messages", m, parser.messages, len(parser.messages))
			parser.messages <- m
		}
	}
}

func GetUnexportedField(field reflect.Value) interface{} {
	return reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Interface()
}

var failMsg int

func (parser *MessageParser) timer(now time.Time, index int) {
	packetLen = 0
	parser.mL[index].Lock()

	packetQueueLen.Set(int64(len(parser.packets)))
	if parser.protocol == ProtocolHTTP2 {
		messageQueueLen.Set(int64(len(parser.m[index])))
		messageQueueLen.Set(int64(len(parser.StreamParser.S)))
		messageQueueLen.Set(int64(len(parser.StreamParser.ConnParser.C)))
	}

	for id, m := range parser.m[index] {
		if now.Sub(m.End) > parser.messageExpire {
			m.TimedOut = true
			stats.Add("message_timeout_count", 1)
			failMsg++
			if parser.End == nil || parser.allowIncompete {
				parser.Emit(m)
			}

			delete(parser.m[index], id)
		}
	}

	parser.mL[index].Unlock()
}

func (parser *MessageParser) Close() error {
	parser.close <- struct{}{}
	if parser.protocol == ProtocolHTTP2 {
		parser.StreamParser.CloseStream <- struct{}{}
		parser.StreamParser.ConnParser.ConnClose <- struct{}{}
	}
	<-parser.close // wait for timer to be closed!
	if parser.protocol == ProtocolHTTP2 {
		<-parser.StreamParser.CloseStream
		<-parser.StreamParser.ConnParser.ConnClose
	}

	return nil
}
