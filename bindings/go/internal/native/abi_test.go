package native

import (
	"testing"
	"unsafe"
)

func TestNativeLayoutMatchesThe64BitCABI(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("typed ABI is limited to 64-bit hosts")
	}
	for _, test := range []struct {
		name      string
		got, want uintptr
	}{
		{"span", unsafe.Sizeof(Span{}), 16},
		{"request field", unsafe.Sizeof(Field{}), 40},
		{"timeout", unsafe.Sizeof(Timeout{}), 16},
		{"retry", unsafe.Sizeof(Retry{}), 96},
		{"request", unsafe.Sizeof(Request{}), 256},
		{"reply", unsafe.Sizeof(Reply{}), 200},
		{"completion field", unsafe.Sizeof(OutputField{}), 40},
		{"hop", unsafe.Sizeof(Hop{}), 72},
		{"event", unsafe.Sizeof(Event{}), 336},
		{"event source opening", unsafe.Sizeof(EventSourceOpening{}), 240},
		{"event source header", unsafe.Sizeof(EventSourceHeader{}), 48},
		{"event source result", unsafe.Sizeof(EventSourceResult{}), 448},
	} {
		if test.got != test.want {
			t.Errorf("%s size=%d, want%d", test.name, test.got, test.want)
		}
	}
}
