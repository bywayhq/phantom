package phantom

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Independent retained Chrome154 Windows ClientHello fields, normalized for
// GREASE: fixtures/tls/chrome/154.0.8037.58/windows-11-26200/client-hello.txt.
const compactCiphers = "1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035"
const compactExtensions = "001b,002d,000b,000a,0005,ca34,000d,0000,44cd,0012,0023,fe0d,0010,0033,0017,002b,ff01"
const compactSignatures = "0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601"
const compactAkamai = "6:131072;4:16777216;2:0;1:65536|16711681|0|m,p,a,s"

func compactJA3(t *testing.T, ciphers string) string {
	t.Helper()
	decimal := func(input string) string {
		parts := strings.Split(input, ",")
		for index, part := range parts {
			value, err := strconv.ParseUint(part, 16, 16)
			if err != nil {
				t.Fatal(err)
			}
			parts[index] = strconv.FormatUint(value, 10)
		}
		return strings.Join(parts, "-")
	}
	return "771," + decimal(ciphers) + "," + decimal(compactExtensions) + "," + decimal("11ec,001d,0017,0018") + ",0"
}

func compactJA4(ciphers string, sorted bool) string {
	extensions := strings.Split(compactExtensions, ",")
	if sorted {
		values := strings.Split(ciphers, ",")
		slices.Sort(values)
		ciphers = strings.Join(values, ",")
		extensions = slices.DeleteFunc(extensions, func(value string) bool { return value == "0000" || value == "0010" })
		slices.Sort(extensions)
	}
	return "t13d1517h2_" + ciphers + "_" + strings.Join(extensions, ",") + "_" + compactSignatures
}

func compactSettings(t *testing.T, owner *Profile) map[string]any {
	t.Helper()
	document, err := owner.Describe()
	if err != nil {
		t.Fatal(err)
	}
	return document["profile"].(map[string]any)
}

func TestCompactTLSOrderingReportsAndBaseOwnership(t *testing.T) {
	base := catalogProfile(t, "fetch")
	before, err := base.ExportJSON()
	if err != nil {
		t.Fatal(err)
	}
	ciphers := strings.Split(compactCiphers, ",")
	ciphers[0], ciphers[1] = ciphers[1], ciphers[0]
	changed := strings.Join(ciphers, ",")
	expected := compactSettings(t, base)["tls"].(map[string]any)["cipher_suites"].([]any)
	expected[0], expected[1] = expected[1], expected[0]
	var fixed *Profile
	for _, importProfile := range []func() (*ImportedProfile, error){
		func() (*ImportedProfile, error) { return ImportJA3Profile(compactJA3(t, changed), base) },
		func() (*ImportedProfile, error) {
			return ImportJA4Profile(compactJA4(changed, false), JA4Original, base)
		},
	} {
		result, err := importProfile()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = result.Profile.Close() })
		settings := compactSettings(t, result.Profile)
		tls := settings["tls"].(map[string]any)
		if result.Profile.CatalogID() != "" || !reflect.DeepEqual(tls["cipher_suites"], expected) || tls["extension_order"].(map[string]any)["kind"] != "Fixed" {
			t.Fatal("lost supplied ordering or invented catalog identity")
		}
		if !slices.Contains(result.ObservedFields, "tls.extension_order") || !slices.Contains(result.SupplementedFields, "tls.ech") {
			t.Fatalf("field provenance: %v / %v", result.ObservedFields, result.SupplementedFields)
		}
		fixed = result.Profile
	}
	result, err := ImportJA4Profile(compactJA4(compactCiphers, true), JA4Sorted, fixed)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Profile.Close()
	if !reflect.DeepEqual(compactSettings(t, result.Profile)["tls"], compactSettings(t, fixed)["tls"]) || slices.Contains(result.ObservedFields, "tls.extension_order") || !slices.Contains(result.SupplementedFields, "tls.extension_order") {
		t.Fatal("sorted input replaced explicit base order or misreported it")
	}
	after, err := base.ExportJSON()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("import changed base: %v", err)
	}
	if err := base.Close(); err != nil {
		t.Fatal(err)
	}
	exported, err := result.Profile.ExportJSON()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := ImportProfileJSON(exported)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	roundtrip, err := restored.ExportJSON()
	if err != nil || !bytes.Equal(exported, roundtrip) {
		t.Fatalf("owned round trip: %v", err)
	}
}

func TestCompactAkamaiTemplatesAndClientSurviveOwnerClosure(t *testing.T) {
	base := catalogProfile(t, "fetch")
	result, err := ImportAkamaiProfile(compactAkamai, base)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Profile.Close()
	settings := compactSettings(t, result.Profile)
	http2 := settings["http2"].(map[string]any)
	var order []string
	for _, entry := range http2["initial_settings"].([]any) {
		order = append(order, entry.(map[string]any)["kind"].(string))
	}
	if !slices.Equal(order, []string{"MaxHeaderListSize", "InitialWindowSize", "EnablePush", "HeaderTableSize"}) || !reflect.DeepEqual(http2["pseudo_header_order"], []any{"Method", "Path", "Authority", "Scheme"}) {
		t.Fatal("Akamai setting/pseudo-header order lost")
	}
	if !reflect.DeepEqual(settings["request_template"], compactSettings(t, base)["request_template"]) || !slices.Contains(result.SupplementedFields, "tls") {
		t.Fatal("base template or provenance lost")
	}
	if _, err := New(Config{ProfileSettings: result.Profile, Protocol: "h1", Context: "fetch"}); kind(err) != "context_unavailable" {
		t.Fatalf("import borrowed catalog ownership: %v", err)
	}
	client, err := New(Config{ProfileSettings: result.Profile, Protocol: "h1", Context: "profile", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := base.Close(); err != nil {
		t.Fatal(err)
	}
	if err := result.Profile.Close(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer server.Close()
	response, err := client.Do(context.Background(), Request{Method: "GET", URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	data, err := response.Body.ReadAll(2)
	if err != nil || string(data) != "ok" {
		t.Fatalf("client retained settings: %q %v", data, err)
	}
}

func TestCompactQUICPreservesObservedOrderAndWidths(t *testing.T) {
	base := catalogProfile(t, "")
	// Supported parameter subsequence from the retained Chrome154 Windows
	// quic-client-hello-1.txt extension57, with original order and widths.
	payload, err := hex.DecodeString("08024064070480600000040480f0000009024067060480600000010480007530200480010000030245c00504806000000f00")
	if err != nil {
		t.Fatal(err)
	}
	result, err := ImportQUICTransportProfile(payload, base)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Profile.Close()
	clear(payload)
	quic := compactSettings(t, result.Profile)["http3"].(map[string]any)["quic_transport"].(map[string]any)
	parameters := quic["wire_parameters"].([]any)
	first := parameters[0].(map[string]any)
	if quic["parameter_order"] != "Fixed" || first["length_width"] != "One" || first["kind"].(map[string]any)["kind"] != "InitialMaxStreamsBidi" || first["kind"].(map[string]any)["value_width"] != "Two" || quic["initial_max_data"] != json.Number("15728640") {
		t.Fatal("QUIC order, widths or values lost")
	}
	if !slices.Contains(result.ObservedFields, "http3.quic_transport.initial_max_data") || !slices.Contains(result.SupplementedFields, "http3.tls") || result.Profile.CatalogID() != "" {
		t.Fatal("QUIC provenance or identity incorrect")
	}
}

func TestCompactImportsRejectLossyMalformedInputsWithRedactedFields(t *testing.T) {
	base := catalogProfile(t, "")
	for _, item := range []struct {
		call  func() (*ImportedProfile, error)
		kind  string
		field string
	}{
		{func() (*ImportedProfile, error) { return ImportJA3Profile(strings.Repeat("a", 32), base) }, "lossy_description", "ja3"},
		{func() (*ImportedProfile, error) { return ImportAkamaiProfile(strings.Repeat("b", 64), base) }, "lossy_description", "akamai"},
		{func() (*ImportedProfile, error) {
			return ImportJA4Profile("t13d1516h2_8daaf6152771_b186095e22b6", JA4Original, base)
		}, "lossy_description", "ja4"},
		{func() (*ImportedProfile, error) { return ImportJA3Profile("private-secret", base) }, "invalid_value", "ja3.version"},
		{func() (*ImportedProfile, error) { return ImportJA3Profile(string([]byte{255}), base) }, "invalid_value", "ja3"},
		{func() (*ImportedProfile, error) { return ImportClientHelloProfile([]byte("private-secret"), base) }, "malformed_description", "client_hello"},
		{func() (*ImportedProfile, error) { return ImportClientHelloProfile(make([]byte, 65537), base) }, "too_large", "client_hello"},
		{func() (*ImportedProfile, error) { return ImportQUICTransportProfile([]byte{1}, base) }, "malformed_description", "http3.quic_transport"},
		{func() (*ImportedProfile, error) { return ImportJA3Profile(strings.Repeat("x", 32769), base) }, "too_large", "ja3"},
		{func() (*ImportedProfile, error) {
			return ImportJA4Profile("private-secret", JA4RawFormat("guess"), base)
		}, "invalid_value", "ja4.format"},
	} {
		result, err := item.call()
		var failure *Error
		if result != nil || !errors.As(err, &failure) || failure.Kind != "profile_import_"+item.kind || failure.Field != item.field {
			t.Fatalf("category/field %s: %v", item.field, err)
		}
		if strings.Contains(fmt.Sprint(err), "private-secret") {
			t.Fatal("error disclosed supplied input")
		}
	}
}

func TestCompactBaseCloseRacesRetainAcquiredSettings(t *testing.T) {
	if _, err := ImportAkamaiProfile(compactAkamai, nil); kind(err) != "profile_closed" {
		t.Fatalf("nil base: %v", err)
	}
	for range 8 {
		base := catalogProfile(t, "")
		var workers sync.WaitGroup
		workers.Go(func() {
			if err := base.Close(); err != nil {
				t.Error(err)
			}
		})
		workers.Go(func() {
			result, err := ImportAkamaiProfile(compactAkamai, base)
			if err != nil {
				if kind(err) != "profile_closed" {
					t.Error(err)
				}
				return
			}
			defer result.Profile.Close()
			if _, err := result.Profile.ExportJSON(); err != nil {
				t.Error(err)
			}
		})
		workers.Wait()
		if _, err := ImportAkamaiProfile(compactAkamai, base); kind(err) != "profile_closed" {
			t.Fatalf("closed base: %v", err)
		}
	}
}
