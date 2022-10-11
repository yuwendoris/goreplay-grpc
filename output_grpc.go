package main

import (
	"encoding/json"
	"fmt"
	"github.com/buger/goreplay/http2_protocol"
	"github.com/buger/goreplay/size"
	"github.com/buger/goreplay/testg"
	"google.golang.org/grpc"
	"log"
	"math"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

type HTTP2OutputConfig struct {
	TrackResponses bool          `json:"output-http2_protocol-track-response"`
	Stats          bool          `json:"output-http2_protocol-stats"`
	WorkersMin     int           `json:"output-http2_protocol-workers-min"`
	WorkersMax     int           `json:"output-http2_protocol-workers"`
	StatsMs        int           `json:"output-http2_protocol-stats-ms"`
	QueueLen       int           `json:"output-http2_protocol-queue-len"`
	Timeout        time.Duration `json:"output-http2_protocol-timeout"`
	WorkerTimeout  time.Duration `json:"output-http2_protocol-worker-timeout"`
	BufferSize     size.Size     `json:"output-http2_protocol-response-buffer"`
	url            *url.URL
}

// BinaryOutput plugin manage pool of workers which send request to replayed server
// By default workers pool is dynamic and starts with 10 workers
// You can specify fixed number of workers using `--output-tcp-workers`
type GRPCOutput struct {
	// Keep this as first element of struct because it guarantees 64bit
	// alignment. atomic.* functions crash on 32bit machines if operand is not
	// aligned at 64bit. See https://github.com/golang/go/issues/599
	activeWorkers int32
	config        *HTTP2OutputConfig
	queueStats    *GorStat
	client        *GRPCClient
	stopWorker    chan struct{}
	queue         chan *Message
	responses     chan *grpcResponse
	stop          chan bool // Channel used only to indicate goroutine should shutdown
}

// HTTPClient holds configurations for a single HTTP client
type GRPCClient struct {
	config *HTTP2OutputConfig
	Client interface{}
}

type grpcResponse struct {
	payload       []byte
	uuid          []byte
	roundTripTime int64
	startedAt     int64
}

// NewBinaryOutput constructor for BinaryOutput
// Initialize workers
func NewGRPCOutput(address string, config *HTTP2OutputConfig) PluginReadWriter {
	o := new(GRPCOutput)
	var err error
	config.url, err = url.Parse(address)
	if err != nil {
		log.Fatal(fmt.Sprintf("[OUTPUT-HTTP] parse HTTP output URL error[%q]", err))
	}
	if config.Timeout < time.Millisecond*100 {
		config.Timeout = time.Second
	}
	if config.BufferSize <= 0 {
		config.BufferSize = 100 * 1024 // 100kb
	}
	if config.WorkersMin <= 0 {
		config.WorkersMin = 1
	}
	if config.WorkersMin > 1000 {
		config.WorkersMin = 1000
	}
	if config.WorkersMax <= 0 {
		config.WorkersMax = math.MaxInt32 // idealy so large
	}
	if config.WorkersMax < config.WorkersMin {
		config.WorkersMax = config.WorkersMin
	}
	if config.QueueLen <= 0 {
		config.QueueLen = 1000
	}
	if config.WorkerTimeout <= 0 {
		config.WorkerTimeout = time.Second * 2
	}
	o.config = config
	o.stop = make(chan bool)
	if o.config.Stats {
		o.queueStats = NewGorStat("output_grpc", o.config.StatsMs)
	}

	o.queue = make(chan *Message, o.config.QueueLen)
	if o.config.TrackResponses {
		o.responses = make(chan *grpcResponse, o.config.QueueLen)
	}
	// it should not be buffered to avoid races
	o.stopWorker = make(chan struct{})

	o.client = NewGRPCClient(o.config)
	o.activeWorkers += int32(o.config.WorkersMin)
	for i := 0; i < o.config.WorkersMin; i++ {
		go o.startWorker()
	}
	go o.workerMaster()

	return o
}

func (o *GRPCOutput) startWorker() {
	for {
		select {
		case <-o.stopWorker:
			return
		case msg := <-o.queue:
			o.sendRequest(o.client, msg)
		}
	}
}

func (o *GRPCOutput) sendRequest(client *GRPCClient, msg *Message) {
	if !isRequestPayload(msg.Meta) {
		return
	}

	uuid := payloadID(msg.Meta)
	start := time.Now()
	resp, err := client.Send(msg.Data)
	stop := time.Now()

	if err != nil {
		Debug(1, fmt.Sprintf("[HTTP2-OUTPUT] error when sending: %q", err))
		return
	}
	if resp == nil {
		return
	}

	if o.config.TrackResponses {
		o.responses <- &grpcResponse{resp, uuid, start.UnixNano(), stop.UnixNano() - start.UnixNano()}
	}
}

func (o *GRPCOutput) workerMaster() {
	var timer = time.NewTimer(o.config.WorkerTimeout)
	defer func() {
		// recover from panics caused by trying to send in
		// a closed chan(o.stopWorker)
		recover()
	}()
	defer timer.Stop()
	for {
		select {
		case <-o.stop:
			return
		default:
			<-timer.C
		}
		// rollback workers
	rollback:
		if atomic.LoadInt32(&o.activeWorkers) > int32(o.config.WorkersMin) && len(o.queue) < 1 {
			// close one worker
			o.stopWorker <- struct{}{}
			atomic.AddInt32(&o.activeWorkers, -1)
			goto rollback
		}
		timer.Reset(o.config.WorkerTimeout)
	}
}

// NewHTTPClient returns new http client with check redirects policy
func NewGRPCClient(config *HTTP2OutputConfig) *GRPCClient {
	client := new(GRPCClient)
	client.config = config

	return client
}

func (c *GRPCClient) Send(data []byte) ([]byte, error) {
	var err error

	req := &http2_protocol.Request{}
	json.Unmarshal(data, req)

	headerData := req.Header
	requestData := req.Data
	// Set up a connection to the server.SayHello
	addr := "127.0.0.1:5555" // todo

	targetPackage, service, method := testg.AnalysisPath(headerData.Method)
	_, outputType := testg.GetRpcInAndOutType(targetPackage, service, method)

	conn, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	serviceName := strings.ToLower(string(service[0])) + service[1:]
	client := testg.GetClient(conn, targetPackage, serviceName)

	rpcDescriptor := testg.GetRpcDescriptor(targetPackage, service, method)

	response, err := testg.CallMethod(client, targetPackage, method, rpcDescriptor, requestData)

	resp := new(http2_protocol.Response)
	resp.Data.DataType = outputType.GetName()
	for _, jj := range response {
		resp.Data.Data = append(resp.Data.Data, jj)
	}

	// 1、能判断是一个conn吗？还有header compression的问题。
	bytes, err := json.Marshal(resp)

	return bytes, err
}

// PluginWrite writes message to this plugin
func (o *GRPCOutput) PluginWrite(msg *Message) (n int, err error) {
	if !isRequestPayload(msg.Meta) {
		return len(msg.Data), nil
	}

	select {
	case <-o.stop:
		return 0, ErrorStopped
	case o.queue <- msg:
	}

	if o.config.Stats {
		o.queueStats.Write(len(o.queue))
	}
	if len(o.queue) > 0 {
		// try to start a new worker to serve
		if atomic.LoadInt32(&o.activeWorkers) < int32(o.config.WorkersMax) {
			go o.startWorker()
			atomic.AddInt32(&o.activeWorkers, 1)
		}
	}
	return len(msg.Data) + len(msg.Meta), nil
}

// PluginRead reads message from this plugin
func (o *GRPCOutput) PluginRead() (*Message, error) {
	if !o.config.TrackResponses {
		return nil, ErrorStopped
	}
	var resp *grpcResponse
	var msg Message
	select {
	case <-o.stop:
		return nil, ErrorStopped
	case resp = <-o.responses:
		msg.Data = resp.payload
	}

	msg.Meta = payloadHeader(ReplayedResponsePayload, resp.uuid, resp.roundTripTime, resp.startedAt)

	return &msg, nil
}
