//go:build (linux || darwin) && cgo

package phantom

/*
#cgo LDFLAGS: -lphantom_go
#include "native.h"
*/
import "C"

import (
	"runtime"
	"unsafe"
)

func nativeDispatch(command, body, output []byte) (int, error) {
	length := C.phantom_go_dispatch((*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(command))), C.size_t(len(command)), (*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(body))), C.size_t(len(body)), (*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(output))), C.size_t(len(output)))
	runtime.KeepAlive(command)
	runtime.KeepAlive(body)
	runtime.KeepAlive(output)
	return int(length), nil
}
func nativeWait(metadata, data []byte) (int, error) {
	length := C.phantom_go_wait((*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(metadata))), C.size_t(len(metadata)), (*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(data))), C.size_t(len(data)))
	runtime.KeepAlive(metadata)
	runtime.KeepAlive(data)
	return int(length), nil
}
