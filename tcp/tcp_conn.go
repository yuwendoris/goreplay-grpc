package tcp

import (
	"bytes"
	"golang.org/x/net/http2/hpack"
)

type Conn struct {
	ConnStream []*Stream
	Enc        *hpack.Encoder
}

type ConnParser struct {
	C map[uint64]*Conn

	streams   chan *Stream
	ConnClose chan struct{}
}

func NewConnParser() (parser *ConnParser) {
	parser = new(ConnParser)

	parser.C = make(map[uint64]*Conn)
	parser.streams = make(chan *Stream, 100)
	parser.ConnClose = make(chan struct{}, 1)

	go parser.wait()

	return parser
}

// Message returns message handler
func (parser *ConnParser) StreamHandler(stream *Stream) {
	parser.streams <- stream
}

func (parser *ConnParser) wait() {
	for {
		select {

		case stream := <-parser.streams:
			parser.processStream(stream)
			// complete channel todo
		case <-parser.ConnClose:
			//parser.ticker.Stop()
			// parser.Close should wait for this function to return
			parser.ConnClose <- struct{}{}
			return
			// default:
		}
	}
}

func (parser *ConnParser) processStream(stream *Stream) {
	if stream == nil {
		return
	}

	connId := stream.Idx

	conn, ok := parser.C[connId]

	switch {
	case ok:
		parser.addStream(conn, stream)

		return
	}

	conn = new(Conn)
	conn.ConnStream = make([]*Stream, 100)
	var buf bytes.Buffer
	conn.Enc = hpack.NewEncoder(&buf)

	parser.C[connId] = conn
	stream.Conn = conn

	parser.addStream(conn, stream)
}

func (parser *ConnParser) addStream(conn *Conn, stream *Stream) bool {
	if !conn.add(stream) {
		return false
	}

	// If we are using protocol parsing, like HTTP, depend on its parsing func.
	// For the binary procols wait for message to expire

	return true
}

// add message to stream
func (c *Conn) add(stream *Stream) bool {
	c.ConnStream = append(c.ConnStream, stream)

	stream.ConnRequest.TransferCompleteChan <- true
	stream.ConnResponse.TransferCompleteChan <- true

	return true
}

func (c *Conn) SetNewCoder() {
	var buf bytes.Buffer
	c.Enc = hpack.NewEncoder(&buf)
}

func (parser *ConnParser) Close() error {
	parser.ConnClose <- struct{}{}
	<-parser.ConnClose // wait for timer to be closed!

	return nil
}
