package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func validConfig() config {
	return config{Name: "control", Protocol: "h2", Profile: "chrome", Route: "direct",
		Concurrency: 2, Requests: 8, Warmup: 2, Bytes: 32768, Method: "GET", CancelStage: "body",
		Consume: "stream", Origins: 1, ChunkBytes: 16384, Workers: 2, DiagnosticSnapshot: true}
}

func TestUnsupportedWorkFailsBeforeWarmup(t *testing.T) {
	for name, change := range map[string]func(*config){
		"protocol":            func(c *config) { c.Protocol = "negotiated" },
		"profile":             func(c *config) { c.Profile = "firefox" },
		"route":               func(c *config) { c.Route = "connect" },
		"method":              func(c *config) { c.Method = "PUT" },
		"upload":              func(c *config) { c.UploadBytes = 1 },
		"redirects":           func(c *config) { c.Redirects = 1 },
		"cancellation":        func(c *config) { c.CancelAfterBytes = 1 },
		"upload cancellation": func(c *config) { c.CancelStage = "upload" },
		"gzip":                func(c *config) { c.Gzip = true },
		"template":            func(c *config) { c.Template = true },
		"workers":             func(c *config) { c.Workers = 3 },
		"speculative":         func(c *config) { c.SpeculativeTLS = true },
		"proxy delay":         func(c *config) { c.ProxyDelayMS = 1 },
		"proxy auth":          func(c *config) { c.ProxyAuth = true },
		"diagnostics":         func(c *config) { c.DiagnosticEvents = 1 },
		"diagnostic snapshot": func(c *config) { c.DiagnosticSnapshot = false },
		"consume":             func(c *config) { c.Consume = "discard" },
		"concurrency":         func(c *config) { c.Concurrency = 257 },
		"requests":            func(c *config) { c.Requests = 0 },
		"warmup":              func(c *config) { c.Warmup = -1 },
		"origins":             func(c *config) { c.Origins = 129 },
		"body":                func(c *config) { c.Bytes = 16*1024*1024 + 1 },
		"chunk":               func(c *config) { c.ChunkBytes = 0 },
		"delay":               func(c *config) { c.ServerDelayMS = 1001 },
		"chunk delay":         func(c *config) { c.ChunkDelayMS = 1001 },
		"arrival":             func(c *config) { c.ArrivalIntervalUS = 1_000_001 },
		"peer workers":        func(c *config) { value := 0; c.PeerWorkers = &value },
	} {
		t.Run(name, func(t *testing.T) {
			c := validConfig()
			change(&c)
			if c.validate() == nil {
				t.Fatal("unsupported work accepted")
			}
		})
	}
}

func TestKnownLengthUploadsAndBodyPrefixCancellation(t *testing.T) {
	for _, protocol := range []string{"h1", "h2", "h3"} {
		c := validConfig()
		c.Protocol, c.Method, c.UploadBytes = protocol, "POST", 16*1024*1024
		if err := c.validate(); err != nil {
			t.Fatal(err)
		}
		c.Method, c.UploadBytes, c.Warmup, c.ChunkDelayMS, c.CancelAfterBytes = "GET", 0, 1, 1, 1024
		if err := c.validate(); err != nil {
			t.Fatal(err)
		}
		for _, change := range []func(*config){
			func(c *config) { c.Consume = "collect" },
			func(c *config) { c.Cold = true },
			func(c *config) { c.Requests = 3 },
			func(c *config) { c.CancelAfterBytes = c.Bytes },
			func(c *config) { c.ChunkDelayMS = 0 },
		} {
			bad := c
			change(&bad)
			if bad.validate() == nil {
				t.Fatal("invalid cancellation work accepted")
			}
		}
	}
}

func TestEveryEffectiveFieldIsRequiredAndRetained(t *testing.T) {
	data, err := json.Marshal(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	c, err := parseConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(c)
	if err != nil || string(encoded) != string(data) {
		t.Fatal("effective configuration changed")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	for key := range fields {
		t.Run(key, func(t *testing.T) {
			copy := make(map[string]json.RawMessage, len(fields))
			for k, value := range fields {
				copy[k] = value
			}
			delete(copy, key)
			missing, err := json.Marshal(copy)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseConfig(missing); err == nil {
				t.Fatal("missing field accepted")
			}
		})
	}
	for _, invalid := range []string{
		strings.Replace(string(data), `"cold":false`, `"cold":null`, 1),
		strings.Replace(string(data), `"cold":false`, `"unknown":false`, 1),
		strings.Replace(string(data), `"requests":8`, `"requests":8.5`, 1),
		string(data) + "{}",
	} {
		if _, err := parseConfig([]byte(invalid)); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
}

func TestWarmColdProtocolsAndScheduledMultiOriginWorkAreSupported(t *testing.T) {
	for _, protocol := range []string{"h1", "h2", "h3"} {
		for _, consume := range []string{"collect", "stream"} {
			for _, cold := range []bool{false, true} {
				c := validConfig()
				c.Protocol, c.Consume, c.Cold, c.Origins, c.ArrivalIntervalUS = protocol, consume, cold, 3, 1000
				if err := c.validate(); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

func TestPeerMustMatchSecureLoopbackWorkload(t *testing.T) {
	for _, raw := range []string{
		"http://127.0.0.1:1234/", "https://example.com:443/", "https://user@127.0.0.1:1234/",
		"https://127.0.0.1/", "https://127.0.0.1:1234/#fragment", "https://127.0.0.1:65536/",
	} {
		if (ready{URLs: []string{raw}, RootDER: []byte{1}}).validate(1) == nil {
			t.Fatal("invalid peer accepted")
		}
	}
	r := ready{URLs: []string{"https://127.0.0.1:1234/"}, RootDER: []byte{1}}
	if err := r.validate(1); err != nil {
		t.Fatal(err)
	}
	if r.validate(2) == nil {
		t.Fatal("wrong origin count accepted")
	}
}
