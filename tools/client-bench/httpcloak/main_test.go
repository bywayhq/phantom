package main

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestCollectionAndStreamingVerifyContentAndLength(t *testing.T) {
	for _, mode := range []string{"collect", "stream"} {
		for _, body := range []string{"ZZZ", "ZZ", "ZZZZ", "ZXZ", ""} {
			c := validConfig()
			c.Consume, c.Bytes = mode, 3
			record := sample{}
			err := consumeBody(strings.NewReader(body), c, &record, time.Now())
			if (err == nil) != (body == "ZZZ") {
				t.Fatalf("%s %q: unexpected result %v", mode, body, err)
			}
			if mode == "collect" && record.FirstByteNS != nil {
				t.Fatal("collection invented a first-delivery timestamp")
			}
			if mode == "stream" && len(body) > 0 && record.FirstByteNS == nil {
				t.Fatal("nonempty stream omitted its first-delivery timestamp")
			}
		}
	}
}

type terminalReader struct{ err error }

func (r terminalReader) Read(buffer []byte) (int, error) {
	buffer[0] = 'Z'
	return 1, r.err
}

func TestStreamingRetainsDataReturnedWithEOFOrError(t *testing.T) {
	failed := errors.New("body interrupted")
	c := validConfig()
	c.Bytes = 1
	for _, terminal := range []error{io.EOF, failed} {
		record := sample{}
		err := consumeBody(terminalReader{terminal}, c, &record, time.Now())
		if record.Bytes != 1 || record.FirstByteNS == nil {
			t.Fatal("data accompanying terminal read was lost")
		}
		if terminal == failed && !errors.Is(err, failed) {
			t.Fatalf("body error was lost: %v", err)
		}
		if terminal == io.EOF && err != nil {
			t.Fatal(err)
		}
	}
}

func TestEmptyBodiesDoNotInventFirstDelivery(t *testing.T) {
	for _, mode := range []string{"collect", "stream"} {
		c := validConfig()
		c.Bytes, c.Consume = 0, mode
		record := sample{}
		if err := consumeBody(strings.NewReader(""), c, &record, time.Now()); err != nil {
			t.Fatal(err)
		}
		if record.FirstByteNS != nil {
			t.Fatal("empty body acquired a first-delivery timestamp")
		}
	}
}
