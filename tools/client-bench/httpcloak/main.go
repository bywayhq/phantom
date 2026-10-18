// Pinned public httpcloak client, independent of Phantom's transport dependencies.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
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

	client "github.com/sardanioss/httpcloak"
)

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
	Error             *string `json:"error"`
}

func newClient(c config, r ready) (*client.Session, error) {
	certificate, err := x509.ParseCertificate(r.RootDER)
	if err != nil {
		return nil, err
	}
	proxyURL, err := r.proxyURL(c)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	opts := []client.SessionOption{
		client.WithTLSConfig(&tls.Config{RootCAs: roots}),
		client.WithSessionTimeout(15 * time.Second), client.WithRedirects(c.Redirects != 0, c.Redirects), client.WithoutRetry(),
		client.WithSessionProxy(proxyURL), client.WithSessionPreferIPv4(), client.WithDisableECH(),
		client.WithLocalAddress("127.0.0.1"), client.WithoutCookieJar(),
		client.WithoutConditionalCache(), client.WithoutHighEntropyClientHints(),
	}
	if !c.Template {
		opts = append(opts, client.WithTLSOnly(), client.WithoutClientHints())
	}
	switch c.Protocol {
	case "h1":
		opts = append(opts, client.WithForceHTTP1())
	case "h2":
		opts = append(opts, client.WithForceHTTP2())
	case "h3":
		opts = append(opts, client.WithForceHTTP3())
	}
	return client.NewSession("chrome-150-windows", opts...), nil
}

func consumeBody(body io.Reader, c config, record *sample, start time.Time) error {
	if c.Consume == "collect" {
		data, err := io.ReadAll(io.LimitReader(body, int64(c.Bytes)+1))
		record.Bytes = len(data)
		if err != nil {
			return err
		}
		if !allZ(data) {
			return errors.New("incorrect response content")
		}
	} else {
		buffer := make([]byte, 32768)
		for {
			n, err := body.Read(buffer)
			if n > 0 {
				if record.FirstByteNS == nil {
					elapsed := time.Since(start).Nanoseconds()
					record.FirstByteNS = &elapsed
				}
				record.Bytes += n
				if !allZ(buffer[:n]) || record.Bytes > c.Bytes {
					return errors.New("incorrect response content or length")
				}
			}
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return err
			}
		}
	}
	if record.Bytes != c.Bytes {
		return errors.New("incorrect response length")
	}
	return nil
}

func allZ(data []byte) bool {
	for _, value := range data {
		if value != 'Z' {
			return false
		}
	}
	return true
}

func request(c config, r ready, shared *client.Session, record *sample, start time.Time) (err error) {
	selected := shared
	if c.Cold {
		selected, err = newClient(c, r)
		if err != nil {
			return err
		}
		record.BuildNS = time.Since(start).Nanoseconds()
		defer selected.Close()
	}
	ctx, cancel := context.WithDeadline(context.Background(), start.Add(15*time.Second))
	defer cancel()
	req := &client.Request{Method: c.Method, URL: r.URLs[record.ID%len(r.URLs)]}
	if c.Method == "POST" {
		req.Body = bytes.NewReader(bytes.Repeat([]byte{'U'}, c.UploadBytes))
	}
	if c.Redirects != 0 {
		response, requestErr := selected.Do(ctx, req)
		if response != nil {
			defer func() { err = errors.Join(err, response.Close()) }()
		}
		if requestErr != nil {
			return requestErr
		}
		if response == nil || response.StatusCode != 200 || response.Protocol != c.Protocol || len(response.History) != c.Redirects {
			return errors.New("unexpected buffered response status, protocol or redirect history")
		}
		if err = consumeBody(response.Body, c, record, start); err != nil {
			return err
		}
		record.CompleteNS = time.Since(start).Nanoseconds()
		return nil
	}
	response, err := selected.DoStream(ctx, req)
	if err != nil {
		return err
	}
	head := time.Since(start).Nanoseconds()
	record.HeadNS = &head
	defer func() { err = errors.Join(err, response.Close()) }()
	if response.StatusCode != 200 || response.Protocol != c.Protocol {
		return errors.New("unexpected response status or protocol")
	}
	if err = consumeBody(response, c, record, start); err != nil {
		return err
	}
	record.CompleteNS = time.Since(start).Nanoseconds()
	return nil
}

func execute(c config, r ready, shared *client.Session, record *sample) {
	start := time.Now()
	if err := request(c, r, shared, record, start); err != nil {
		record.CompleteNS = time.Since(start).Nanoseconds()
		message := err.Error()
		record.Error = &message
	}
}

func signal(event string) error {
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"event": event})
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

func run(c config, r ready, output string) error {
	runtime.GOMAXPROCS(c.Workers)
	shared, err := newClient(c, r)
	if err != nil {
		return err
	}
	defer shared.Close()
	var warmup sync.WaitGroup
	failures := make(chan error, c.Concurrency)
	for worker := range c.Concurrency {
		warmup.Go(func() {
			for id := worker; id < c.Warmup; id += c.Concurrency {
				record := sample{ID: id}
				execute(c, r, shared, &record)
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
		"config": c, "elapsed_ns": elapsed, "heap_instrumented": false,
		"observer_storage_bytes": observerBytes, "samples": samples,
		"adapter_settings": map[string]any{
			"library": "httpcloak=1.7.3", "recipe": "chrome-150-windows",
			"automatic_headers": c.Template, "retry": false, "redirects": c.Redirects,
			"cookies": false, "conditional_cache": false, "high_entropy_client_hints": false,
			"route": c.Route, "proxy_auth": c.ProxyAuth, "application_timeout_ms": 15000,
			"connect_timeout_ms": nil, "connect_timeout_note": "library defaults, bounded by the total context deadline",
			"pool_limits": "library defaults", "runtime_gomaxprocs": c.Workers,
			"h1_streaming_reuse": false,
			"streaming_api":      c.Redirects == 0,
			"go_version":         runtime.Version(),
		},
	}
	if c.Redirects != 0 {
		result["unavailable_timings"] = map[string]string{"head_ns": "The buffered redirect API returns after body delivery."}
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
		return errors.New("usage: phantom-httpcloak-bench run CONFIG READY RESULT")
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
