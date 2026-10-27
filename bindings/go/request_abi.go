package phantom

import (
	"unsafe"

	"github.com/bywayhq/phantom/bindings/go/internal/native"
)

func boolean(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}

func requestContextFlags(context string) (uint64, error) {
	var code uint64
	switch context {
	case "":
	case "raw":
		code = 1
	case "navigation":
		code = 2
	case "fetch":
		code = 3
	case "fetchNoStore":
		code = 4
	case "fetchUpload":
		code = 5
	case "script":
		code = 6
	case "stylesheet":
		code = 7
	case "image":
		code = 8
	case "font":
		code = 9
	default:
		return 0, &Error{Kind: "invalid_context"}
	}
	return code << 5, nil
}

func pointed(value *uint64) uint64 {
	if value == nil {
		return 0
	}
	return *value
}

func nativeRetryValue(value wireRetryPolicy) (*native.Retry, []uint16) {
	result := &native.Retry{}
	if item := value.Connection; item != nil {
		result.Flags |= 1
		result.ConnectionMaximum = item.Maximum
		result.ConnectionDelay = item.DelayNS
		if item.MaximumDelayNS != nil {
			result.Flags |= 2
			result.ConnectionMaximumDelay = *item.MaximumDelayNS
		}
		if item.FullJitter {
			result.Flags |= 4
		}
	}
	var statuses []uint16
	if item := value.Status; item != nil {
		result.Flags |= 8
		result.StatusMaximum = item.Maximum
		result.StatusDelay = item.DelayNS
		for _, status := range item.Statuses {
			statuses = append(statuses, uint16(status))
		}
		result.Statuses = unsafe.Pointer(unsafe.SliceData(statuses))
		result.StatusCount = uint64(len(statuses))
		if item.MaximumDelayNS != nil {
			result.Flags |= 16
			result.StatusMaximumDelay = *item.MaximumDelayNS
		}
		if item.FullJitter {
			result.Flags |= 32
		}
		if item.RetryAfterLimitNS != nil {
			result.Flags |= 64
			result.RetryAfter = *item.RetryAfterLimitNS
		}
	}
	if value.ReusedConnectionReplay {
		result.Flags |= 128
	}
	if value.UnprocessedReplays != nil {
		result.Flags |= 256
		result.Unprocessed = *value.UnprocessedReplays
	}
	if value.MaximumRetries != nil {
		result.Flags |= 512
		result.Maximum = *value.MaximumRetries
	}
	if value.HTTP2Fallback {
		result.Flags |= 1024
	}
	return result, statuses
}
