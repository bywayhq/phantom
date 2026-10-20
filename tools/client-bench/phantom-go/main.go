// Public Go binding adapter for the existing controlled-peer benchmark.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"time"

	phantom "github.com/bywayhq/phantom/bindings/go"
)

const profile = "chrome/154.0.8037.97/windows-11-26200/r1"

type sample struct {
	ID                int     `json:"id"`
	ScheduledNS       int64   `json:"scheduled_ns"`
	StartedNS         int64   `json:"started_ns"`
	ApplicationWaitNS int64   `json:"application_wait_ns"`
	BuildNS           int64   `json:"build_ns"`
	HeadNS            *int64  `json:"head_ns"`
	FirstByteNS       *int64  `json:"first_byte_ns"`
	CompleteNS        int64   `json:"complete_ns"`
	Bytes             int     `json:"bytes"`
	Cancelled         bool    `json:"cancelled"`
	Error             *string `json:"error"`
}

func newClient(c config, r ready) (*phantom.Client, error) {
	return phantom.New(phantom.Config{
		Profile: profile, Protocol: c.Protocol, Context: "raw", DisableCookies: true,
		AdditionalRootsDER: [][]byte{r.RootDER},
		Timeouts:           phantom.Timeouts{Connect: phantom.LimitTimeout(5 * time.Second), Total: phantom.LimitTimeout(15 * time.Second)},
	})
}

func allZ(data []byte) bool {
	for _, value := range data {
		if value != 'Z' {
			return false
		}
	}
	return true
}

func consume(body *phantom.Body, c config, record *sample, start time.Time) error {
	if c.Consume == "collect" {
		data, err := body.ReadAll(c.Bytes)
		record.Bytes = len(data)
		if err != nil {
			return err
		}
		if !allZ(data) {
			return errors.New("incorrect response content")
		}
	} else {
		return consumeStream(body, c, record, start)
	}
	if record.Bytes != c.Bytes {
		return errors.New("incorrect response length")
	}
	return nil
}

func consumeStream(body io.Reader, c config, record *sample, start time.Time) error {
	cancel := c.CancelAfterBytes != 0 && record.ID%2 == 0
	buffer := make([]byte, 65536)
	if cancel {
		buffer = buffer[:min(len(buffer), c.CancelAfterBytes)]
	}
	for {
		n, err := body.Read(buffer)
		if n > 0 {
			if record.FirstByteNS == nil {
				elapsed := time.Since(start).Nanoseconds()
				record.FirstByteNS = &elapsed
			}
			record.Bytes += n
			if record.Bytes > c.Bytes || !allZ(buffer[:n]) {
				return errors.New("incorrect response content or length")
			}
		}
		if cancel && record.Bytes >= c.CancelAfterBytes {
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			if record.Bytes >= c.Bytes {
				return errors.New("body finished before cancellation")
			}
			record.Cancelled = true
			return nil
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
	}
	if record.Bytes != c.Bytes {
		return errors.New("incorrect response length")
	}
	return nil
}

type upload struct {
	remaining int
	chunk     []byte
}

func newUpload(size int) *upload {
	return &upload{remaining: size, chunk: bytes.Repeat([]byte{'U'}, min(size, 65536))}
}

func (source *upload) Read(output []byte) (int, error) {
	if len(output) == 0 {
		return 0, nil
	}
	if source.remaining == 0 {
		return 0, io.EOF
	}
	n := copy(output, source.chunk[:min(source.remaining, len(source.chunk))])
	source.remaining -= n
	return n, nil
}

func (source *upload) Close() error { return nil }

func request(c config, r ready, shared *phantom.Client, record *sample, start time.Time) (err error) {
	selected := shared
	var owned *phantom.Client
	var response *phantom.Response
	defer func() {
		record.CompleteNS = time.Since(start).Nanoseconds()
		if response != nil {
			err = errors.Join(err, response.Body.Close())
		}
		if owned != nil {
			err = errors.Join(err, owned.Close())
		}
	}()
	if c.Cold {
		owned, err = newClient(c, r)
		if err != nil {
			return err
		}
		selected = owned
		record.BuildNS = time.Since(start).Nanoseconds()
	}
	target := r.URLs[record.ID%len(r.URLs)]
	if c.CancelAfterBytes != 0 && record.ID%2 == 0 {
		target += "?cancel=1"
	}
	req := phantom.Request{Method: c.Method, URL: target}
	if c.Method == "POST" {
		length := uint64(c.UploadBytes)
		req.Upload, req.UploadLength = newUpload(c.UploadBytes), &length
	}
	response, err = selected.Do(context.Background(), req)
	if err != nil {
		return err
	}
	head := time.Since(start).Nanoseconds()
	record.HeadNS = &head
	if response.Status != 200 || response.Protocol != c.Protocol || response.EffectiveURL != target ||
		response.RedirectsFollowed != 0 || response.ConnectionSetupRetries != 0 || len(response.DecodedContentCodings) != 0 {
		return errors.New("unexpected status, protocol, destination or replay")
	}
	return consume(response.Body, c, record, start)
}

func execute(c config, r ready, shared *phantom.Client, record *sample) {
	if err := request(c, r, shared, record, time.Now()); err != nil {
		record.Cancelled = false
		message := err.Error()
		record.Error = &message
	}
}

func signal(event string) error {
	message := map[string]any{"event": event}
	if event == "ready" {
		message["pid"] = os.Getpid()
	}
	return json.NewEncoder(os.Stdout).Encode(message)
}

func control(input *bufio.Reader, expected string) error {
	line, err := input.ReadString('\n')
	if err != nil {
		return err
	}
	if strings.TrimSpace(line) != expected {
		return errors.New("controller sent an invalid command")
	}
	return nil
}

func run(c config, r ready, output string) (err error) {
	runtime.GOMAXPROCS(c.Workers)
	shared, err := newClient(c, r)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, shared.Close()) }()
	var warmup sync.WaitGroup
	failures := make(chan error, c.Concurrency)
	for worker := range c.Concurrency {
		warmup.Go(func() {
			for id := worker; id < c.Warmup; id += c.Concurrency {
				record := sample{ID: id}
				warm := c
				warm.CancelAfterBytes = 0
				execute(warm, r, shared, &record)
				if record.Error != nil {
					failures <- fmt.Errorf("warmup failed: %s", *record.Error)
					return
				}
			}
		})
	}
	warmup.Wait()
	close(failures)
	for failure := range failures {
		err = errors.Join(err, failure)
	}
	if err != nil {
		return err
	}
	samples := make([]sample, c.Requests)
	for id := range samples {
		samples[id].ID = id
	}
	observerBytes := uintptr(cap(samples)) * reflect.TypeFor[sample]().Size()
	input := bufio.NewReader(os.Stdin)
	if err := signal("ready"); err != nil {
		return err
	}
	if err := control(input, "go"); err != nil {
		return err
	}
	start := time.Now()
	var workers sync.WaitGroup
	for worker := range c.Concurrency {
		workers.Go(func() {
			for id := worker; id < len(samples); id += c.Concurrency {
				record := &samples[id]
				planned := time.Duration(c.ArrivalIntervalUS*uint64(id)) * time.Microsecond
				if c.ArrivalIntervalUS != 0 {
					time.Sleep(time.Until(start.Add(planned)))
				}
				record.StartedNS = time.Since(start).Nanoseconds()
				record.ScheduledNS = record.StartedNS
				if c.ArrivalIntervalUS != 0 {
					record.ScheduledNS = planned.Nanoseconds()
				}
				record.ApplicationWaitNS = max(0, record.StartedNS-record.ScheduledNS)
				execute(c, r, shared, record)
			}
		})
	}
	workers.Wait()
	elapsed := time.Since(start).Nanoseconds()
	if err := signal("phase_end"); err != nil {
		return err
	}
	if err := control(input, "save"); err != nil {
		return err
	}
	result := map[string]any{
		"config": c, "samples": samples, "elapsed_ns": elapsed, "heap_instrumented": false,
		"observer_storage_bytes": observerBytes,
		"adapter_settings": map[string]any{
			"library": "phantom-go (repository binding)", "recipe": profile, "context": "raw",
			"go_version": runtime.Version(), "runtime_gomaxprocs": c.Workers, "native_workers": 2,
			"stream_chunk_bytes": 65536, "cookies": false, "route": "direct",
			"cancellation_read_bytes": min(65536, c.CancelAfterBytes),
			"upload_source":           "one-shot known-length producer; source chunk <=65536 bytes",
			"connect_timeout_ms":      5000, "total_timeout_ms": 15000,
			"retries": false, "redirects": false, "pool_limits": "library defaults",
			"native_capacity": "binding defaults: 64 clients, bodies and ordinary operations",
		},
	}
	file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	err = json.NewEncoder(file).Encode(result)
	if err = errors.Join(err, file.Close()); err != nil {
		return err
	}
	return signal("saved")
}

func main() {
	if err := mainResult(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func mainResult() error {
	if len(os.Args) != 5 || os.Args[1] != "run" {
		return errors.New("usage: phantom-go-bench run CONFIG READY RESULT")
	}
	data, err := os.ReadFile(os.Args[2])
	if err != nil {
		return err
	}
	c, err := parseConfig(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}))
	if err != nil {
		return err
	}
	var r ready
	if err := readJSON(os.Args[3], &r); err != nil {
		return err
	}
	if err := r.validate(c.Origins); err != nil {
		return err
	}
	return run(c, r, os.Args[4])
}
