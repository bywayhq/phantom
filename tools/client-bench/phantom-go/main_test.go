package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
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

func TestKnownLengthUploadSourceIsBounded(t *testing.T) {
	for _, size := range []int{0, 1, 65536, 65537, 16 * 1024 * 1024} {
		source := newUpload(size)
		if len(source.chunk) > 65536 {
			t.Fatal("unbounded upload source")
		}
		output := make([]byte, 70000)
		count := 0
		for {
			n, err := source.Read(output)
			for _, value := range output[:n] {
				if value != 'U' {
					t.Fatal("incorrect upload byte")
				}
			}
			count += n
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		if count != size {
			t.Fatal("incorrect upload length")
		}
	}
}

func TestPrefixCancellationLeavesHealthyBodyComplete(t *testing.T) {
	c := validConfig()
	c.Bytes, c.CancelAfterBytes = 8, 2
	for _, id := range []int{0, 1} {
		record := sample{ID: id}
		if err := consumeStream(strings.NewReader("ZZZZZZZZ"), c, &record, time.Now()); err != nil {
			t.Fatal(err)
		}
		if record.Cancelled != (id == 0) || record.Bytes != map[int]int{0: 2, 1: 8}[id] {
			t.Fatal("selected prefix or healthy completion differs")
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
