package http2_protocol

import (
	"bytes"
	"fmt"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"io"
	"io/ioutil"
)

// transfer []byte to frame
func TransferFrame(payloads []byte) http2.Frame {
	buf := bytes.NewBuffer(payloads)
	framer := http2.NewFramer(ioutil.Discard, buf)
	framer.MaxHeaderListSize = uint32(16 << 20)
	framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	frame, err := framer.ReadFrame()
	if err == io.EOF {
		// todo error
	}

	if err != nil {
		fmt.Println("err",err, payloads)
	}

	return frame
}

func GetSteamId(frame http2.Frame) uint32 {
	return frame.Header().StreamID
}

func GetType(frame http2.Frame) string {
	return frame.Header().Type.String()
}

func HasHeaderEnd(frame *http2.MetaHeadersFrame) bool {
	return frame.StreamEnded()
}

type ProtocolStateSetter interface {
	SetProtocolState(interface{})
	ProtocolState() interface{}
}

func HasFullPayload(frame http2.Frame) bool {
	switch dd := frame.(type) {
	case *http2.DataFrame:
		return dd.StreamEnded()
	case *http2.MetaHeadersFrame:
		return dd.StreamEnded()
	default:
		return false
	}
}

func IsResponse(frame http2.Frame) bool {
	switch frameType := frame.(type) {
	case *http2.MetaHeadersFrame:
		for _, hf := range frameType.Fields {
			if hf.Name == ":status" {
				return true
			}
		}
	}

	return false
}

func IsRequest(frame http2.Frame) bool {
	switch frameType := frame.(type) {
	case *http2.MetaHeadersFrame:
		for _, hf := range frameType.Fields {
			if hf.Name == ":path" {
				return true
			}
		}
	}

	return false
}

func CheckMagic(frameBytes []byte) bool {
	if bytes.Equal(frameBytes, []byte{80, 82, 73, 32, 42, 32, 72, 84, 84, 80, 47, 50, 46, 48, 13, 10, 13, 10, 83, 77, 13, 10, 13, 10}) {
		return true
	}

	return false
}