package tcp

import (
	"fmt"
	"google.golang.org/protobuf/runtime/protoiface"
)

// 对于stream进行处理
type Stream struct {
	GrpcInput protoiface.MessageV1
	GrpcOutput protoiface.MessageV1

	Conn *Conn
	Idx   uint64
	ConnRequest *Message
	ConnResponse *Message
}

type StreamParser struct {
	S  map[uint64]*Stream

	Conn          *Conn
	ConnParser     *ConnParser
	messages      chan *Message
	CloseStream          chan struct{}
}

func NewStreamParser() (parser *StreamParser) {
	parser = new(StreamParser)

	parser.messages = make(chan *Message, 10000)

	parser.S = make(map[uint64]*Stream)

	parser.CloseStream = make(chan struct{}, 1)

	go parser.wait()

	return parser
}

// Message returns message handler
func (parser *StreamParser) MessageHandler(message *Message) {
	parser.messages <- message
}

func (parser *StreamParser) wait() {
	for {
		select {
		case message := <-parser.messages:
			parser.processMessage(message)
		case <-parser.CloseStream:
			// parser.Close should wait for this function to return
			parser.CloseStream <- struct{}{}
			return
			// default:
		}
	}
}

func (parser *StreamParser)processMessage(message *Message) {
	if message == nil {
		return
	}

	streamId := message.StreamId  // 计算streamId，问题在于stream的处理上

	s, ok := parser.S[streamId]

	switch {
	case ok:

		parser.addMessage(s, message)

		return
	}

	s = new(Stream)
	s.Idx = message.ConnId

	parser.S[streamId] = s
	message.Stream = s
	fmt.Println("message.Stream 1111", message.Stream)

	parser.addMessage(s, message)
}

// 为啥会有多个stream呢?
func (parser *StreamParser) addMessage(stream *Stream, message *Message) bool {
	if !stream.add(message) {
		return false
	}

	// If we are using protocol parsing, like HTTP, depend on its parsing func.
	// For the binary procols wait for message to expire
	if parser.end(stream) {
		parser.emit(stream)
		return true
	}

	return true
}

// add message to stream
func (s *Stream)add(message *Message) bool {
	if message.Direction == DirIncoming {
		s.ConnRequest = message
	} else if message.Direction == DirOutcoming {
		s.ConnResponse = message
	}

	return true
}

// check stream is end
func (parser *StreamParser)end(stream *Stream) bool {
	if stream.ConnResponse != nil {
		return true
	}

	return false
}

// streamHandler处理
func (parser *StreamParser)emit(s *Stream) {
	// 这里不做删除操作
	// 处理conn handler
	parser.ConnParser.StreamHandler(s)

	//fmt.Println("parser.streams", s)
	//parser.streams <- s
}

// find request within response
func (s *Stream)GetRequest() *Message {
	return s.ConnRequest
}