package main

import (
	"crypto/tls"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"time"
)

// TCPOutput used for sending raw tcp payloads
// Currently used for internal communication between listener and replay server
// Can be used for transfering binary payloads like protocol buffers
type TCPOutput struct {
	address     string
	limit       int
	buf         []chan []byte
	bufStats    *GorStat
	config      *TCPOutputConfig
	workerIndex uint32
}

// TCPOutputConfig tcp output configuration
type TCPOutputConfig struct {
	Secure     bool `json:"output-tcp-secure"`
	Sticky     bool `json:"output-tcp-sticky"`
	SkipVerify bool `json:"output-tcp-skip-verify"`
	Workers    int  `json:"output-tcp-workers"`
}

// NewTCPOutput constructor for TCPOutput
// Initialize X workers which hold keep-alive connection
func NewTCPOutput(address string, config *TCPOutputConfig) io.Writer {
	o := new(TCPOutput)

	o.address = address
	o.config = config

	if Settings.OutputTCPStats {
		o.bufStats = NewGorStat("output_tcp", 5000)
	}

	// create X buffers and send the buffer index to the worker
	o.buf = make([]chan []byte, o.config.Workers)
	for i := 0; i < o.config.Workers; i++ {
		o.buf[i] = make(chan []byte, 100)
		go o.worker(i)
	}

	return o
}

func (o *TCPOutput) worker(bufferIndex int) {
	retries := 0
	conn, err := o.connect(o.address)
	for {
		if err == nil {
			break
		}

		Debug(1, fmt.Sprintf("Can't connect to aggregator instance, reconnecting in 1 second. Retries:%d", retries))
		time.Sleep(1 * time.Second)

		conn, err = o.connect(o.address)
		retries++
	}

	if retries > 0 {
		Debug(2, fmt.Sprintf("Connected to aggregator instance after %d retries", retries))
	}

	defer conn.Close()

	for {
		data := <-o.buf[bufferIndex]
		if _, err = conn.Write(data); err == nil {
			_, err = conn.Write([]byte(payloadSeparator))
		}

		if err != nil {
			Debug(2, "INFO: TCP output connection closed, reconnecting")
			o.buf[bufferIndex] <- data
			go o.worker(bufferIndex)
			break
		}
	}
}

func (o *TCPOutput) getBufferIndex(data []byte) int {
	if !o.config.Sticky {
		o.workerIndex++
		return int(o.workerIndex) % o.config.Workers
	}

	hasher := fnv.New32a()
	hasher.Write(payloadMeta(data)[1])
	return int(hasher.Sum32()) % o.config.Workers

}

func (o *TCPOutput) Write(data []byte) (n int, err error) {
	if !isOriginPayload(data) {
		return len(data), nil
	}

	// We have to copy, because sending data in multiple threads
	newBuf := make([]byte, len(data))
	copy(newBuf, data)

	bufferIndex := o.getBufferIndex(data)
	o.buf[bufferIndex] <- newBuf

	if Settings.OutputTCPStats {
		o.bufStats.Write(len(o.buf[bufferIndex]))
	}

	return len(data), nil
}

func (o *TCPOutput) connect(address string) (conn net.Conn, err error) {
	if o.config.Secure {
		conn, err = tls.Dial("tcp", address, &tls.Config{InsecureSkipVerify: o.config.SkipVerify})
	} else {
		conn, err = net.Dial("tcp", address)
	}

	return
}

func (o *TCPOutput) String() string {
	return fmt.Sprintf("TCP output %s, limit: %d", o.address, o.limit)
}
