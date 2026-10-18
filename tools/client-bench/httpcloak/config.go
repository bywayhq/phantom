package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strconv"
)

type config struct {
	Name               string `json:"name"`
	Protocol           string `json:"protocol"`
	Profile            string `json:"profile"`
	Route              string `json:"route"`
	Concurrency        int    `json:"concurrency"`
	Requests           int    `json:"requests"`
	Warmup             int    `json:"warmup"`
	Bytes              int    `json:"bytes"`
	Method             string `json:"method"`
	UploadBytes        int    `json:"upload_bytes"`
	Redirects          int    `json:"redirects"`
	Consume            string `json:"consume"`
	Cold               bool   `json:"cold"`
	Origins            int    `json:"origins"`
	ServerDelayMS      uint64 `json:"server_delay_ms"`
	ChunkBytes         int    `json:"chunk_bytes"`
	ChunkDelayMS       uint64 `json:"chunk_delay_ms"`
	Gzip               bool   `json:"gzip"`
	Template           bool   `json:"template"`
	ArrivalIntervalUS  uint64 `json:"arrival_interval_us"`
	Workers            int    `json:"workers"`
	PeerWorkers        *int   `json:"peer_workers"`
	SpeculativeTLS     bool   `json:"speculative_tls"`
	ProxyDelayMS       uint64 `json:"proxy_delay_ms"`
	DiagnosticEvents   int    `json:"diagnostic_events"`
	DiagnosticSnapshot bool   `json:"diagnostic_snapshot"`
}

func parseConfig(data []byte) (config, error) {
	var c config
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return c, err
	}
	// The controller supplies every effective setting, including false values.
	// Missing settings must not quietly inherit Go's zero values.
	t := reflect.TypeFor[config]()
	if len(fields) != t.NumField() {
		return c, errors.New("configuration must contain every effective field")
	}
	for i := range t.NumField() {
		key := t.Field(i).Tag.Get("json")
		value, exists := fields[key]
		if !exists || (key != "peer_workers" && bytes.Equal(bytes.TrimSpace(value), []byte("null"))) {
			return c, fmt.Errorf("missing or null configuration field %q", key)
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&c); err != nil {
		return c, err
	}
	return c, c.validate()
}

func (c config) validate() error {
	if c.Protocol != "h1" && c.Protocol != "h2" && c.Protocol != "h3" {
		return errors.New("httpcloak requires exact h1, h2 or h3")
	}
	if c.Profile != "chrome" || c.Route != "direct" || c.Gzip ||
		c.SpeculativeTLS || c.ProxyDelayMS != 0 || c.DiagnosticEvents != 0 {
		return errors.New("httpcloak requires Chrome, direct routing and no optional work")
	}
	if (c.Consume != "stream" && c.Consume != "collect") ||
		c.Concurrency < 1 || c.Concurrency > 256 || c.Requests < 1 || c.Requests > 1_000_000 ||
		c.Warmup < 0 || c.Warmup > 100_000 || c.Origins < 1 || c.Origins > 128 ||
		c.Bytes < 0 || c.Bytes > 16*1024*1024 || c.ChunkBytes < 1 || c.ChunkBytes > 65536 ||
		(c.Method != "GET" && c.Method != "POST") || c.UploadBytes < 0 || c.UploadBytes > 16*1024*1024 ||
		(c.Method == "GET" && c.UploadBytes != 0) ||
		c.Redirects < 0 || c.Redirects > 3 ||
		(c.Redirects != 0 && (c.Method != "GET" || c.Consume != "collect")) ||
		c.Workers < 1 || c.Workers > 16 ||
		(c.PeerWorkers != nil && (*c.PeerWorkers < 1 || *c.PeerWorkers > 16)) ||
		c.ServerDelayMS > 1000 || c.ChunkDelayMS > 1000 || c.ArrivalIntervalUS > 1_000_000 {
		return errors.New("invalid or unbounded httpcloak benchmark configuration")
	}
	return nil
}

type ready struct {
	URLs    []string `json:"urls"`
	RootDER []byte   `json:"root_der"`
}

func (r ready) validate(origins int) error {
	if len(r.URLs) != origins || len(r.RootDER) == 0 {
		return errors.New("peer identity differs from the configured workload")
	}
	for _, raw := range r.URLs {
		u, err := url.Parse(raw)
		if err != nil {
			return err
		}
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 || u.Scheme != "https" ||
			u.Hostname() != "127.0.0.1" || u.User != nil || u.Fragment != "" {
			return errors.New("httpcloak requires HTTPS peers on IPv4 loopback")
		}
	}
	return nil
}

func readJSON(path string, target any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}
