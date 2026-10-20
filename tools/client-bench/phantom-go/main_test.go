package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestPayloadValidationAndControlCommands(t *testing.T) {
	if !allZ(nil) || !allZ([]byte("ZZZZ")) || allZ([]byte("ZZXZ")) {
		t.Fatal("payload validation differs")
	}
	if err := control(bufio.NewReader(strings.NewReader("go\n")), "go"); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"save\n", "", "go"} {
		if control(bufio.NewReader(strings.NewReader(input)), "go") == nil {
			t.Fatal("invalid controller command accepted")
		}
	}
}

func TestNewSamplesKeepUnavailableTimesNull(t *testing.T) {
	data, err := json.Marshal(sample{ID: 3})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range [][]byte{[]byte(`"head_ns":null`), []byte(`"first_byte_ns":null`), []byte(`"error":null`)} {
		if !bytes.Contains(data, field) {
			t.Fatalf("sample lacks %s", field)
		}
	}
}
