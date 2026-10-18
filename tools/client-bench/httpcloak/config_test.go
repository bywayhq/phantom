package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func validConfig() config {
	return config{Name: "control", Protocol: "h2", Profile: "chrome", Route: "direct",
		Concurrency: 2, Requests: 8, Warmup: 2, Bytes: 32768, Method: "GET", Consume: "stream",
		Origins: 1, ChunkBytes: 1024, ChunkDelayMS: 1, Workers: 2, Template: true,
		DiagnosticSnapshot: true}
}

func TestUnsupportedWorkFailsBeforeWarmup(t *testing.T) {
	for name, change := range map[string]func(*config){
		"protocol":           func(c *config) { c.Protocol = "construct" },
		"profile":            func(c *config) { c.Profile = "firefox" },
		"proxy":              func(c *config) { c.Route = "connect" },
		"gzip":               func(c *config) { c.Gzip = true },
		"speculative":        func(c *config) { c.SpeculativeTLS = true },
		"diagnostics":        func(c *config) { c.DiagnosticEvents = 1 },
		"workers":            func(c *config) { c.Workers = 0 },
		"concurrency":        func(c *config) { c.Concurrency = 257 },
		"body":               func(c *config) { c.Bytes = 16*1024*1024 + 1 },
		"upload":             func(c *config) { c.UploadBytes = 1 },
		"upload limit":       func(c *config) { c.Method = "POST"; c.UploadBytes = 16*1024*1024 + 1 },
		"method":             func(c *config) { c.Method = "PATCH" },
		"redirect bound":     func(c *config) { c.Redirects = 4 },
		"redirect streaming": func(c *config) { c.Redirects = 1 },
		"redirect upload":    func(c *config) { c.Redirects = 1; c.Method = "POST"; c.Consume = "collect" },
	} {
		t.Run(name, func(t *testing.T) {
			c := validConfig()
			change(&c)
			if c.validate() == nil {
				t.Fatal("unsupported configuration was accepted")
			}
		})
	}
}

func TestEveryEffectiveFieldIsRequired(t *testing.T) {
	data, err := json.Marshal(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseConfig(data); err != nil {
		t.Fatal(err)
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
				t.Fatal("omitted effective field was accepted")
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
			t.Fatalf("invalid configuration accepted: %s", invalid)
		}
	}
}

func TestColdScheduledMultiOriginWorkIsSupported(t *testing.T) {
	for _, protocol := range []string{"h1", "h2", "h3"} {
		c := validConfig()
		c.Protocol, c.Consume, c.Cold, c.Origins, c.ArrivalIntervalUS = protocol, "collect", true, 3, 1000
		if err := c.validate(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPeerMustMatchSecureLoopbackWorkload(t *testing.T) {
	for _, raw := range []string{
		"http://127.0.0.1:1234/", "https://example.com:443/", "https://user@127.0.0.1:1234/",
		"https://127.0.0.1/", "https://127.0.0.1:1234/#fragment", "https://127.0.0.1:65536/",
	} {
		r := ready{URLs: []string{raw}, RootDER: []byte{1}}
		if r.validate(1) == nil {
			t.Fatalf("invalid peer accepted: %s", raw)
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
