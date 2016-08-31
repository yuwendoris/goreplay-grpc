package main

import (
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	_ "net/http/httputil"
	"sync"
	"testing"
	"time"
)

func TestHTTPOutput(t *testing.T) {
	wg := new(sync.WaitGroup)
	quit := make(chan int)

	input := NewTestInput()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("User-Agent") != "Gor" {
			t.Error("Wrong header")
		}

		if req.Method == "OPTIONS" {
			t.Error("Wrong method")
		}

		if req.Method == "POST" {
			defer req.Body.Close()
			body, _ := ioutil.ReadAll(req.Body)

			if string(body) != "a=1&b=2" {
				t.Error("Wrong POST body:", string(body))
			}
		}

		wg.Done()
	}))
	defer server.Close()

	headers := HTTPHeaders{HTTPHeader{"User-Agent", "Gor"}}
	methods := HTTPMethods{[]byte("GET"), []byte("PUT"), []byte("POST")}
	Settings.modifierConfig = HTTPModifierConfig{headers: headers, methods: methods}

	output := NewHTTPOutput(server.URL, &HTTPOutputConfig{Debug: true})

	Plugins.Inputs = []io.Reader{input}
	Plugins.Outputs = []io.Writer{output}

	go Start(quit)

	for i := 0; i < 100; i++ {
		wg.Add(2) // OPTIONS should be ignored
		input.EmitPOST()
		input.EmitOPTIONS()
		input.EmitGET()
	}

	if output.(*HTTPOutput).activeWorkers < 50 {
		t.Error("Should create workers for each request", output.(*HTTPOutput).activeWorkers)
	}

	wg.Wait()
	close(quit)

	Settings.modifierConfig = HTTPModifierConfig{}
}

func TestHTTPOutputKeepOriginalHost(t *testing.T) {
	wg := new(sync.WaitGroup)
	quit := make(chan int)

	input := NewTestInput()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Host != "custom-host.com" {
			t.Error("Wrong header", req.Host)
		}

		wg.Done()
	}))
	defer server.Close()

	headers := HTTPHeaders{HTTPHeader{"Host", "custom-host.com"}}
	Settings.modifierConfig = HTTPModifierConfig{headers: headers}

	output := NewHTTPOutput(server.URL, &HTTPOutputConfig{Debug: false, OriginalHost: true})

	Plugins.Inputs = []io.Reader{input}
	Plugins.Outputs = []io.Writer{output}

	go Start(quit)

	wg.Add(1)
	input.EmitGET()

	wg.Wait()

	close(quit)

	Settings.modifierConfig = HTTPModifierConfig{}
}

func TestHTTPOutputSSL(t *testing.T) {
	wg := new(sync.WaitGroup)
	quit := make(chan int)

	// Origing and Replay server initialization
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wg.Done()
	}))

	input := NewTestInput()
	output := NewHTTPOutput(server.URL, &HTTPOutputConfig{})

	Plugins.Inputs = []io.Reader{input}
	Plugins.Outputs = []io.Writer{output}

	go Start(quit)

	wg.Add(2)

	input.EmitPOST()
	input.EmitGET()

	wg.Wait()
	close(quit)
}

func TestHTTPOutputSessions(t *testing.T) {
	wg := new(sync.WaitGroup)
	quit := make(chan int)

	input := NewTestInput()
	input.disableHeaders = true

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		wg.Done()
	}))
	defer server.Close()

	Settings.recognizeTCPSessions = true
	output := NewHTTPOutput(server.URL, &HTTPOutputConfig{Debug: true})

	Plugins.Inputs = []io.Reader{input}
	Plugins.Outputs = []io.Writer{output}

	go Start(quit)

	uuid1 := []byte("1234567890123456789a0000")
	uuid2 := []byte("1234567890123456789d0000")


	for i := 0; i < 100; i++ {
		wg.Add(1) // OPTIONS should be ignored
		copy(uuid1[20:], randByte(4))
		input.EmitBytes([]byte("1 " + string(uuid1) + " 1\n" + "GET / HTTP/1.1\r\n\r\n"))
	}

	for i := 0; i < 100; i++ {
		wg.Add(1) // OPTIONS should be ignored
		copy(uuid2[20:], randByte(4))
		input.EmitBytes([]byte("1 " + string(uuid2) + " 1\n" + "GET / HTTP/1.1\r\n\r\n"))
	}

	wg.Wait()

	if output.(*HTTPOutput).activeWorkers != 2 {
		t.Error("Should have only 2 workers", output.(*HTTPOutput).activeWorkers)
	}

	close(quit)

	Settings.recognizeTCPSessions = false
}

func BenchmarkHTTPOutput(b *testing.B) {
	wg := new(sync.WaitGroup)
	quit := make(chan int)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		wg.Done()
	}))
	defer server.Close()

	input := NewTestInput()
	output := NewHTTPOutput(server.URL, &HTTPOutputConfig{})

	Plugins.Inputs = []io.Reader{input}
	Plugins.Outputs = []io.Writer{output}

	go Start(quit)

	for i := 0; i < b.N; i++ {
		wg.Add(1)
		input.EmitPOST()
	}

	wg.Wait()

	close(quit)
}
