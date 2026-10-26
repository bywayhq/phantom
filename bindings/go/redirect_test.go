package phantom

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRedirectPolicyInheritanceReplacementAndBoundedHistory(t *testing.T) {
	var mu sync.Mutex
	var targets []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		targets = append(targets, r.RequestURI)
		mu.Unlock()
		switch r.URL.Path {
		case "/start":
			w.Header().Set("Location", "middle")
			w.WriteHeader(302)
		case "/middle":
			w.Header().Set("Location", "/final%2Fpath?x=a%20b")
			w.WriteHeader(307)
		default:
			_, _ = io.WriteString(w, "ok")
		}
	}))
	defer server.Close()
	for _, test := range []struct {
		name    string
		client  RedirectPolicy
		request *RedirectPolicy
		history *uint64
		status  int
		failure string
		want    []string
	}{
		{"default", RedirectPolicy{}, nil, nil, 302, "", []string{"/start"}},
		{"client limited", RedirectPolicy{MaximumHops: 2}, nil, uint64Pointer(1), 200, "", []string{"/start", "/middle", "/final%2Fpath?x=a%20b"}},
		{"request disables", RedirectPolicy{MaximumHops: 2}, &RedirectPolicy{}, uint64Pointer(1), 302, "", []string{"/start"}},
		{"request enables", RedirectPolicy{}, &RedirectPolicy{MaximumHops: 2}, nil, 200, "", []string{"/start", "/middle", "/final%2Fpath?x=a%20b"}},
		{"exhausted", RedirectPolicy{MaximumHops: 1}, nil, uint64Pointer(2), 0, "redirect", []string{"/start", "/middle"}},
		{"zero history", RedirectPolicy{}, nil, uint64Pointer(0), 0, "invalid_redirect_history", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			mu.Lock()
			targets = nil
			mu.Unlock()
			client, err := New(Config{Profile: profile, Protocol: "h1", RedirectPolicy: test.client, Timeout: 5 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			response, err := client.Do(context.Background(), Request{Method: "GET", URL: server.URL + "/start", RedirectPolicy: test.request, RedirectHistoryLimit: test.history})
			if test.failure != "" {
				if kind(err) != test.failure || response != nil {
					t.Fatalf("response=%v, error=%v", response, err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if response.Status != test.status {
					t.Fatalf("status=%d", response.Status)
				}
				if _, err := response.Body.ReadAll(2); err != nil {
					t.Fatal(err)
				}
				if test.history == nil {
					if response.RedirectHistory != nil {
						t.Fatal("unsolicited history")
					}
				} else if response.RedirectHistory == nil {
					t.Fatal("missing enabled history")
				} else if test.status == 302 {
					if len(response.RedirectHistory.Entries) != 0 || response.RedirectHistory.OmittedHops != 0 {
						t.Fatal("nonempty disabled history")
					}
				} else {
					history := response.RedirectHistory
					if len(history.Entries) != 1 || history.OmittedHops != 1 || response.RedirectsFollowed != 2 || response.EffectiveURL != server.URL+"/final%2Fpath?x=a%20b" {
						t.Fatalf("metadata: %v", history)
					}
					hop := history.Entries[0]
					if hop.FromURL != server.URL+"/start" || hop.ToURL != server.URL+"/middle" || hop.Method != "GET" || hop.NextMethod != "GET" || hop.Status != 302 {
						t.Fatalf("hop=%v", hop)
					}
				}
			}
			mu.Lock()
			actual := append([]string(nil), targets...)
			mu.Unlock()
			if !reflect.DeepEqual(actual, test.want) {
				t.Fatalf("traffic=%v, want=%v", actual, test.want)
			}
		})
	}
}

func uint64Pointer(value uint64) *uint64 { return &value }

func TestRedirectRequestPoliciesAreOwnedBeforeAsyncWork(t *testing.T) {
	entered := make(chan struct{})
	resume := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			close(entered)
			select {
			case <-resume:
			case <-r.Context().Done():
				return
			}
			w.Header().Set("Location", "/done")
			w.WriteHeader(302)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()
	client, err := New(Config{Profile: profile, Protocol: "h1", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer func() {
		select {
		case <-resume:
		default:
			close(resume)
		}
	}()
	policy := RedirectPolicy{MaximumHops: 1}
	limit := uint64(1)
	type result struct {
		response *Response
		err      error
	}
	finished := make(chan result, 1)
	go func() {
		response, err := client.Do(context.Background(), Request{Method: "GET", URL: server.URL + "/start", RedirectPolicy: &policy, RedirectHistoryLimit: &limit})
		finished <- result{response, err}
	}()
	select {
	case <-entered:
	case outcome := <-finished:
		t.Fatalf("request stopped before peer: %v", outcome.err)
	case <-time.After(5 * time.Second):
		t.Fatal("request did not enter peer")
	}
	policy.MaximumHops = 0
	limit = 0
	close(resume)
	outcome := <-finished
	if outcome.err != nil {
		t.Fatal(outcome.err)
	}
	if _, err := outcome.response.Body.ReadAll(2); err != nil {
		t.Fatal(err)
	}
	if outcome.response.RedirectHistory == nil || len(outcome.response.RedirectHistory.Entries) != 1 {
		t.Fatal("caller mutation changed submitted policy")
	}
}

func TestRedirectMethodsReplayAndCrossOriginCredentials(t *testing.T) {
	for _, status := range []int{303, 307, 308} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			type observed struct{ method, body, auth, cookie, safe, custom string }
			received := make(chan observed, 1)
			destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				received <- observed{r.Method, string(body), r.Header.Get("Authorization"), r.Header.Get("Cookie"), r.Header.Get("X-Safe"), r.Header.Get("X-Api-Key")}
				_, _ = io.WriteString(w, "ok")
			}))
			defer destination.Close()
			var original atomic.Int64
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				original.Add(1)
				body, err := io.ReadAll(r.Body)
				if err != nil || r.Method != "POST" || string(body) != "upload" || r.Header.Get("Authorization") != "Bearer secret" || r.Header.Get("Cookie") != "secret=value" || r.Header.Get("X-Api-Key") != "custom-secret" {
					t.Errorf("origin request differs: %s %q %v", r.Method, body, err)
				}
				w.Header().Set("Location", destination.URL+"/final")
				w.WriteHeader(status)
			}))
			defer source.Close()
			client, err := New(Config{Profile: profile, Protocol: "h1", DisableCookies: true, RedirectPolicy: RedirectPolicy{MaximumHops: 1, CredentialHeaders: []string{"x-api-key"}}, Timeout: 5 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			response, err := client.Do(context.Background(), Request{Method: "POST", URL: source.URL, Body: []byte("upload"), Headers: []Header{
				{Name: "Authorization", Value: []byte("Bearer secret")}, {Name: "Cookie", Value: []byte("secret=value")}, {Name: "X-Safe", Value: []byte("retained")}, {Name: "X-Api-Key", Value: []byte("custom-secret")}}, RedirectHistoryLimit: uint64Pointer(1)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := response.Body.ReadAll(2); err != nil {
				t.Fatal(err)
			}
			got := <-received
			method, body := "POST", "upload"
			if status == 303 {
				method, body = "GET", ""
			}
			if got != (observed{method, body, "", "", "retained", ""}) || original.Load() != 1 {
				t.Fatalf("destination=%v, original=%d", got, original.Load())
			}
			if response.RedirectHistory == nil || len(response.RedirectHistory.Entries) != 1 || response.RedirectHistory.Entries[0].NextMethod != method {
				t.Fatal("method history differs")
			}
		})
	}
}

func TestRedirectsChargeSharedAttemptBudgetAndBoundMetadata(t *testing.T) {
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/budget" {
			w.Header().Set("Location", "/done")
			w.WriteHeader(302)
			return
		}
		if r.URL.Path == "/large" {
			var hop int
			_, _ = fmt.Sscan(r.URL.Query().Get("hop"), &hop)
			if hop < 20 {
				w.Header().Set("Location", fmt.Sprintf("/large?hop=%d&padding=%s", hop+1, strings.Repeat("a", 8000)))
				w.WriteHeader(302)
				return
			}
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()
	client, err := New(Config{Profile: profile, Protocol: "h1", RedirectPolicy: RedirectPolicy{MaximumHops: 20}, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	budget, err := NewAttemptBudget(1)
	if err != nil {
		t.Fatal(err)
	}
	defer budget.Close()
	response, err := client.Do(context.Background(), Request{Method: "GET", URL: server.URL + "/budget", Budget: budget})
	if kind(err) != "attempt_budget_exhausted" || response != nil || hits.Load() != 1 {
		t.Fatalf("budget=%v, hits=%d", err, hits.Load())
	}
	response, err = client.Do(context.Background(), Request{Method: "GET", URL: server.URL + "/large", RedirectHistoryLimit: uint64Pointer(20)})
	if kind(err) != "metadata_limit" || response != nil || hits.Load() != 22 {
		t.Fatalf("metadata=%v, hits=%d", err, hits.Load())
	}
	response, err = client.Do(context.Background(), Request{Method: "GET", URL: server.URL + "/done", RedirectHistoryLimit: uint64Pointer(1)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := response.Body.ReadAll(2); err != nil {
		t.Fatal(err)
	}
	if response.RedirectHistory == nil || len(response.RedirectHistory.Entries) != 0 {
		t.Fatal("cleanup/control history differs")
	}
	secret := "private-query"
	history := RedirectHistory{Entries: []RedirectHop{{FromURL: secret, ToURL: secret, Status: 302}}}
	for _, value := range []string{fmt.Sprint(history), fmt.Sprintf("%#v", history), fmt.Sprint(history.Entries[0]), fmt.Sprintf("%#v", history.Entries[0])} {
		if strings.Contains(value, secret) {
			t.Fatal("history formatting leaks URLs")
		}
	}
}

func TestRedirectCredentialNamesAreCopiedAndBounded(t *testing.T) {
	input := RedirectPolicy{MaximumHops: 1, CredentialHeaders: []string{"x-api-key"}}
	wire, err := redirectPolicyWire(input)
	if err != nil {
		t.Fatal(err)
	}
	input.CredentialHeaders[0] = "changed"
	if wire.CredentialHeaders[0] != "x-api-key" {
		t.Fatal("names were not owned")
	}
	for _, names := range [][]string{make([]string, 257), {strings.Repeat("x", 65537)}} {
		if _, err := redirectPolicyWire(RedirectPolicy{CredentialHeaders: names}); kind(err) != "input_limit" {
			t.Fatalf("unexpected error: %v", err)
		}
	}
}
