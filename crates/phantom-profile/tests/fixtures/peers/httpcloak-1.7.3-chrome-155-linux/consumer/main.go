package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sardanioss/httpcloak"
	"github.com/sardanioss/httpcloak/fingerprint"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if os.Getenv("SSLKEYLOGFILE") != "" {
		return fmt.Errorf("SSLKEYLOGFILE must be unset")
	}
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		if os.Getenv(name) != "" {
			return fmt.Errorf("proxy environment must be unset: %s", name)
		}
	}
	if len(os.Args) != 6 {
		return fmt.Errorf("usage: peer CERT BASE_URL OUTPUT baseline|boundary RUN_TOKEN")
	}
	certificate, err := os.ReadFile(os.Args[1])
	if err != nil {
		return fmt.Errorf("read certificate: %w", err)
	}
	if len(certificate) > 65536 {
		return fmt.Errorf("certificate PEM exceeds 65536 bytes")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		return fmt.Errorf("certificate PEM is invalid")
	}
	base, err := url.Parse(os.Args[2])
	if err != nil {
		return fmt.Errorf("parse origin: %w", err)
	}
	if base.Scheme != "https" || base.Hostname() != "server.phantom.test" || base.Port() == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || (base.Path != "" && base.Path != "/") {
		return fmt.Errorf("origin must be https://server.phantom.test:PORT")
	}
	port, err := strconv.Atoi(base.Port())
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("origin port is invalid")
	}
	if len(os.Args[5]) == 0 || len(os.Args[5]) > 64 || strings.IndexFunc(os.Args[5], func(c rune) bool {
		return !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-')
	}) >= 0 {
		return fmt.Errorf("run token must contain 1 to 64 lowercase letters, digits or hyphens")
	}
	const preset = "chrome-155-linux"
	p := fingerprint.LookupCustom(preset)
	if p == nil || p.Name != preset {
		return fmt.Errorf("exact embedded preset is unavailable")
	}
	description, err := fingerprint.Describe(preset)
	if err != nil {
		return fmt.Errorf("describe preset: %w", err)
	}
	if err := writeNewFile(filepath.Join(os.Args[3], "effective-preset.json"), []byte(description)); err != nil {
		return err
	}
	session := httpcloak.NewSession(preset,
		httpcloak.WithSessionTimeout(15*time.Second),
		httpcloak.WithForceHTTP2(),
		httpcloak.WithTLSConfig(&tls.Config{RootCAs: roots}),
		httpcloak.WithConnectTo("server.phantom.test", "127.0.0.1"),
		httpcloak.WithoutRetry(), httpcloak.WithoutRedirects(),
		httpcloak.WithoutCookieJar(), httpcloak.WithoutConditionalCache(),
		httpcloak.WithoutHighEntropyClientHints(), httpcloak.WithDisableECH(),
	)
	defer session.Close()
	type request struct {
		label   string
		headers map[string][]string
	}
	requests := []request{{"first", nil}, {"reused", nil}}
	switch os.Args[4] {
	case "baseline":
	case "boundary":
		// HPACK size includes 32 bytes plus the name and value lengths.
		// The unchanged peer SETTINGS table size is 4096.
		field := func(size int) map[string][]string {
			return map[string][]string{"X-Hpack-Size": {strings.Repeat("x", size-32-len("x-hpack-size"))}}
		}
		marker := map[string][]string{"X-Table-Marker": {"retained-marker"}}
		requests = append(requests,
			request{"cookie-first", map[string][]string{"Cookie": {"one=alpha; two=beta"}}},
			request{"cookie-reused", map[string][]string{"Cookie": {"one=alpha; two=beta"}}},
			request{"above-three-quarters", field(3073)},
			request{"full-table", field(4096)},
			request{"marker-before-oversized", marker},
			request{"oversized", field(4097)},
			request{"marker-after-oversized", marker},
		)
	default:
		return fmt.Errorf("mode must be baseline or boundary")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for index, item := range requests {
		target := *base
		target.Path = "/ws.html"
		if index == len(requests)-1 {
			target.Path = "/done"
		}
		target.RawQuery = url.Values{"run": {os.Args[5]}, "case": {item.label}}.Encode()
		requestContext, requestCancel := context.WithTimeout(ctx, 15*time.Second)
		response, err := session.DoStream(requestContext, &httpcloak.Request{Method: "GET", URL: target.String(), Headers: item.headers})
		if err != nil {
			requestCancel()
			return fmt.Errorf("request %d %s: %w", index+1, item.label, err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response, 4097))
		closeErr := response.Close()
		requestCancel()
		if readErr != nil || closeErr != nil {
			return fmt.Errorf("read or close response %d: %w", index+1, errors.Join(readErr, closeErr))
		}
		if len(body) > 4096 {
			return fmt.Errorf("response %d: body exceeds 4096 bytes", index+1)
		}
		expectedStatus, expectedBody := 200, []byte("peer capture\n")
		if target.Path == "/done" {
			expectedStatus, expectedBody = 204, nil
		}
		if response.Protocol != "h2" || response.StatusCode != expectedStatus || response.FinalURL != target.String() || response.ContentLength != int64(len(expectedBody)) || !bytes.Equal(body, expectedBody) {
			return fmt.Errorf("response %d: protocol=%s status=%d bytes=%d", index+1, response.Protocol, response.StatusCode, len(body))
		}
		headerBytes := 0
		headerFields := 0
		for name, values := range response.Headers {
			for _, value := range values {
				headerFields++
				headerBytes += len(name) + len(value)
			}
		}
		if headerFields > 16 || headerBytes > 4096 || len(response.Headers["cache-control"]) != 1 || response.Headers["cache-control"][0] != "no-store" {
			return fmt.Errorf("response %d: unexpected header inventory", index+1)
		}
		if err := writeNewFile(filepath.Join(os.Args[3], fmt.Sprintf("response-%d.body", index+1)), body); err != nil {
			return err
		}
		if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"request": index + 1, "case": item.label, "protocol": response.Protocol, "status": response.StatusCode, "body_bytes": len(body), "response_header_fields": headerFields, "response_header_bytes": headerBytes, "response_headers": response.Headers}); err != nil {
			return err
		}
	}
	return nil
}

func writeNewFile(name string, data []byte) error {
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}
