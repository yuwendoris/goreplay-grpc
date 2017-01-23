package main

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/buger/gor-pro/proto"
)

var _ = fmt.Println

const initialDynamicWorkers = 10

type httpWorker struct {
	output       *HTTPOutput
	client       *HTTPClient
	lastActivity time.Time
	queue        chan []byte
	stop         chan bool
}

func newHTTPWorker(output *HTTPOutput, queue chan []byte) *httpWorker {
	client := NewHTTPClient(output.address, &HTTPClientConfig{
		FollowRedirects:    output.config.redirectLimit,
		Debug:              output.config.Debug,
		OriginalHost:       output.config.OriginalHost,
		Timeout:            output.config.Timeout,
		ResponseBufferSize: output.config.BufferSize,
	})

	w := &httpWorker{client: client}
	if queue == nil {
		w.queue = make(chan []byte, 100)
	} else {
		w.queue = queue
	}
	w.stop = make(chan bool)

	go func() {
		for {
			select {
			case payload := <-w.queue:
				output.sendRequest(client, payload)
			case <-w.stop:
				return
			}
		}
	}()

	return w
}

type response struct {
	payload       []byte
	uuid          []byte
	roundTripTime int64
	startedAt     int64
}

// HTTPOutputConfig struct for holding http output configuration
type HTTPOutputConfig struct {
	redirectLimit int

	stats   bool
	workers int

	elasticSearch string

	Timeout      time.Duration
	OriginalHost bool
	BufferSize   int

	Debug bool

	TrackResponses bool
}

// HTTPOutput plugin manage pool of workers which send request to replayed server
// By default workers pool is dynamic and starts with 10 workers
// You can specify fixed number of workers using `--output-http-workers`
type HTTPOutput struct {
	// Keep this as first element of struct because it guarantees 64bit
	// alignment. atomic.* functions crash on 32bit machines if operand is not
	// aligned at 64bit. See https://github.com/golang/go/issues/599
	activeWorkers int64

	workerSessions map[string]*httpWorker

	address string
	limit   int
	queue   chan []byte

	responses chan response

	needWorker chan int

	config *HTTPOutputConfig

	queueStats *GorStat

	elasticSearch *ESPlugin
}

// NewHTTPOutput constructor for HTTPOutput
// Initialize workers
func NewHTTPOutput(address string, config *HTTPOutputConfig) io.Writer {
	o := new(HTTPOutput)

	o.address = address
	o.config = config

	if o.config.stats {
		o.queueStats = NewGorStat("output_http")
	}

	o.queue = make(chan []byte, 1000)
	o.responses = make(chan response, 1000)
	o.needWorker = make(chan int, 1)

	// Initial workers count
	if o.config.workers == 0 {
		o.needWorker <- initialDynamicWorkers
	} else {
		o.needWorker <- o.config.workers
	}

	if o.config.elasticSearch != "" {
		o.elasticSearch = new(ESPlugin)
		o.elasticSearch.Init(o.config.elasticSearch)
	}

	if Settings.recognizeTCPSessions {
		o.workerSessions = make(map[string]*httpWorker, 100)
		go o.sessionWorkerMaster()
	} else {
		go o.workerMaster()
	}

	return o
}

func (o *HTTPOutput) workerMaster() {
	for {
		newWorkers := <-o.needWorker
		atomic.AddInt64(&o.activeWorkers, int64(newWorkers))
		for i := 0; i < newWorkers; i++ {
			go o.startWorker()
		}

		// Disable dynamic scaling if workers poll fixed size
		if o.config.workers != 0 {
			return
		}
	}
}

func (o *HTTPOutput) sessionWorkerMaster() {
	gc := time.Tick(time.Second)

	for {
		select {
		case p := <-o.queue:
			id := payloadID(p)
			sessionID := string(id[0:20])
			worker, ok := o.workerSessions[sessionID]

			if !ok {
				atomic.AddInt64(&o.activeWorkers, 1)
				worker = newHTTPWorker(o, nil)
				o.workerSessions[sessionID] = worker
			}

			worker.queue <- p
			worker.lastActivity = time.Now()
		case <-gc:
			now := time.Now()

			for id, w := range o.workerSessions {
				if !w.lastActivity.IsZero() && now.Sub(w.lastActivity) >= 60*time.Second {
					w.stop <- true
					delete(o.workerSessions, id)
					atomic.AddInt64(&o.activeWorkers, -1)
				}
			}
		}
	}
}

func (o *HTTPOutput) startWorker() {
	client := NewHTTPClient(o.address, &HTTPClientConfig{
		FollowRedirects:    o.config.redirectLimit,
		Debug:              o.config.Debug,
		OriginalHost:       o.config.OriginalHost,
		Timeout:            o.config.Timeout,
		ResponseBufferSize: o.config.BufferSize,
	})

	for {
		select {
		case data := <-o.queue:
			o.sendRequest(client, data)
		case <-time.After(2 * time.Second):
			// When dynamic scaling enabled workers die after 2s of inactivity
			if o.config.workers > 0 {
				continue
			}

			workersCount := atomic.LoadInt64(&o.activeWorkers)

			// At least 1 startWorker should be alive
			if workersCount != 1 {
				atomic.AddInt64(&o.activeWorkers, -1)
				return
			}
		}
	}
}

func (o *HTTPOutput) Write(data []byte) (n int, err error) {
	if !isRequestPayload(data) {
		return len(data), nil
	}

	buf := make([]byte, len(data))
	copy(buf, data)

	o.queue <- buf

	if o.config.stats {
		o.queueStats.Write(len(o.queue))
	}

	if !Settings.recognizeTCPSessions && o.config.workers == 0 {
		workersCount := atomic.LoadInt64(&o.activeWorkers)

		if len(o.queue) > int(workersCount) {
			o.needWorker <- len(o.queue)
		}
	}

	return len(data), nil
}

func (o *HTTPOutput) Read(data []byte) (int, error) {
	resp := <-o.responses

	Debug("[OUTPUT-HTTP] Received response:", string(resp.payload))

	header := payloadHeader(ReplayedResponsePayload, resp.uuid, resp.roundTripTime, resp.startedAt)
	copy(data[0:len(header)], header)
	copy(data[len(header):], resp.payload)

	return len(resp.payload) + len(header), nil
}

func (o *HTTPOutput) sendRequest(client *HTTPClient, request []byte) {
	meta := payloadMeta(request)
	if len(meta) < 2 {
		return
	}
	uuid := meta[1]

	body := payloadBody(request)
	if !proto.IsHTTPPayload(body) {
		return
	}

	start := time.Now()
	resp, err := client.Send(body)
	stop := time.Now()

	if err != nil {
		Debug("Request error:", err)
	}

	if o.config.TrackResponses {
		o.responses <- response{resp, uuid, start.UnixNano(), stop.UnixNano() - start.UnixNano()}
	}

	if o.elasticSearch != nil {
		o.elasticSearch.ResponseAnalyze(request, resp, start, stop)
	}
}

func (o *HTTPOutput) String() string {
	return "HTTP output: " + o.address
}
