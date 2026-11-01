package phantom

import (
	"time"
	"unicode/utf8"

	"github.com/bywayhq/phantom/bindings/go/internal/native"
)

func stateTimestamp(value time.Time) native.StateTimestamp {
	return native.StateTimestamp{Seconds: value.Unix(), Nanoseconds: uint64(value.Nanosecond())}
}

func projectTimestamp(value native.StateTimestamp) (time.Time, error) {
	if value.Nanoseconds >= 1_000_000_000 {
		return time.Time{}, &Error{Kind: "native_abi"}
	}
	result := time.Unix(value.Seconds, int64(value.Nanoseconds)).UTC()
	if result.Unix() != value.Seconds {
		return time.Time{}, &Error{Kind: "native_abi"}
	}
	return result, nil
}

func stateTextSize(size int, values ...string) (int, error) {
	for _, value := range values {
		if len(value) > native.MaxStateText-size {
			return 0, &Error{Kind: "input_limit"}
		}
		if !utf8.ValidString(value) {
			return 0, &Error{Kind: "invalid_state_snapshot"}
		}
		size += len(value)
	}
	return size, nil
}

func putStateText(arena *[]byte, value string) native.Slice {
	result := native.Slice{Offset: uint64(len(*arena)), Length: uint64(len(value))}
	*arena = append(*arena, value...)
	return result
}

func cookieTransfer(snapshot CookieSnapshot) ([]native.StateCookie, []byte, error) {
	if !snapshot.Enabled {
		return nil, nil, &Error{Kind: "invalid_state_snapshot"}
	}
	if len(snapshot.Entries) > native.MaxStateCookies {
		return nil, nil, &Error{Kind: "input_limit"}
	}
	size := 0
	for _, entry := range snapshot.Entries {
		var err error
		size, err = stateTextSize(size, entry.Name, entry.Value, entry.Domain, entry.Path)
		if err != nil {
			return nil, nil, err
		}
		if entry.PartitionKey != nil {
			size, err = stateTextSize(size, *entry.PartitionKey)
			if err != nil {
				return nil, nil, err
			}
		}
		if entry.SourceScheme != CookieHTTP && entry.SourceScheme != CookieHTTPS {
			return nil, nil, &Error{Kind: "invalid_cookie_source_scheme"}
		}
		if entry.SameSite != "" && entry.SameSite != CookieSameSiteStrict && entry.SameSite != CookieSameSiteLax && entry.SameSite != CookieSameSiteNone {
			return nil, nil, &Error{Kind: "invalid_cookie_same_site"}
		}
	}
	rows := make([]native.StateCookie, len(snapshot.Entries))
	arena := make([]byte, 0, size)
	for index, entry := range snapshot.Entries {
		row := native.StateCookie{Name: putStateText(&arena, entry.Name), Value: putStateText(&arena, entry.Value),
			Domain: putStateText(&arena, entry.Domain), Path: putStateText(&arena, entry.Path), SourceScheme: 1}
		if entry.SourceScheme == CookieHTTPS {
			row.SourceScheme = 2
		}
		if entry.HostOnly {
			row.Flags |= 1
		}
		if entry.Secure {
			row.Flags |= 2
		}
		if entry.HTTPOnly {
			row.Flags |= 4
		}
		if entry.PartitionKey != nil {
			row.Flags |= 8
			row.PartitionKey = putStateText(&arena, *entry.PartitionKey)
		}
		if entry.ExpiresAt != nil {
			row.Flags |= 16
			row.Expiry = stateTimestamp(*entry.ExpiresAt)
		}
		switch entry.SameSite {
		case CookieSameSiteStrict:
			row.SameSite = 1
		case CookieSameSiteLax:
			row.SameSite = 2
		case CookieSameSiteNone:
			row.SameSite = 3
		}
		rows[index] = row
	}
	return rows, arena, nil
}

func altSvcTransfer(snapshot AltSvcSnapshot) ([]native.StateAlternative, []byte, error) {
	if !snapshot.Enabled {
		return nil, nil, &Error{Kind: "invalid_state_snapshot"}
	}
	if len(snapshot.Entries) > native.MaxStateAlternatives {
		return nil, nil, &Error{Kind: "input_limit"}
	}
	size := 0
	for _, entry := range snapshot.Entries {
		var err error
		size, err = stateTextSize(size, entry.Origin, entry.Host)
		if err != nil {
			return nil, nil, err
		}
	}
	rows := make([]native.StateAlternative, len(snapshot.Entries))
	arena := make([]byte, 0, size)
	for index, entry := range snapshot.Entries {
		rows[index] = native.StateAlternative{Origin: putStateText(&arena, entry.Origin), Host: putStateText(&arena, entry.Host),
			Port: uint64(entry.Port), Expiry: stateTimestamp(entry.ExpiresAt)}
	}
	return rows, arena, nil
}

func ticketRoutes(input []SessionRoute) ([]native.StateRoute, error) {
	if len(input) > 256 {
		return nil, &Error{Kind: "input_limit"}
	}
	size := 0
	for _, route := range input {
		values := []string{route.Proxy}
		if route.ProxyCredentials != nil {
			values = append(values, route.ProxyCredentials.Username, route.ProxyCredentials.Password)
		}
		for _, value := range values {
			if len(value) > 64*1024-size {
				return nil, &Error{Kind: "input_limit"}
			}
			if !utf8.ValidString(value) {
				return nil, &Error{Kind: "invalid_proxy_credentials"}
			}
			size += len(value)
		}
	}
	rows := make([]native.StateRoute, len(input))
	for index, route := range input {
		rows[index].Proxy = native.BorrowedString(route.Proxy)
		if route.ProxyCredentials != nil {
			rows[index].Credentials = 1
			rows[index].Username = native.BorrowedString(route.ProxyCredentials.Username)
			rows[index].Password = native.BorrowedString(route.ProxyCredentials.Password)
		}
	}
	return rows, nil
}

func stateString(arena []byte, span native.Slice) (string, error) {
	if span.Offset > uint64(len(arena)) || span.Length > uint64(len(arena))-span.Offset {
		return "", &Error{Kind: "native_abi"}
	}
	bytes := arena[span.Offset : span.Offset+span.Length]
	if !utf8.Valid(bytes) {
		return "", &Error{Kind: "native_abi"}
	}
	return string(bytes), nil
}

func projectCookies(result stateResult) (CookieSnapshot, error) {
	snapshot := CookieSnapshot{Enabled: result.value.Enabled == 1, Entries: make([]CookieEntry, len(result.cookies))}
	for index, row := range result.cookies {
		if row.Flags & ^uint64(31) != 0 || row.SourceScheme < 1 || row.SourceScheme > 2 || row.SameSite > 3 ||
			(row.Flags&8 == 0 && row.PartitionKey.Length != 0) || (row.Flags&16 == 0 && row.Expiry != (native.StateTimestamp{})) {
			return CookieSnapshot{}, &Error{Kind: "native_abi"}
		}
		entry := CookieEntry{SourceScheme: CookieHTTP, HostOnly: row.Flags&1 != 0, Secure: row.Flags&2 != 0, HTTPOnly: row.Flags&4 != 0}
		if row.SourceScheme == 2 {
			entry.SourceScheme = CookieHTTPS
		}
		switch row.SameSite {
		case 1:
			entry.SameSite = CookieSameSiteStrict
		case 2:
			entry.SameSite = CookieSameSiteLax
		case 3:
			entry.SameSite = CookieSameSiteNone
		}
		for _, field := range []struct {
			span   native.Slice
			output *string
		}{
			{row.Name, &entry.Name}, {row.Value, &entry.Value}, {row.Domain, &entry.Domain}, {row.Path, &entry.Path},
		} {
			value, err := stateString(result.arena, field.span)
			if err != nil {
				return CookieSnapshot{}, err
			}
			*field.output = value
		}
		if row.Flags&8 != 0 {
			value, err := stateString(result.arena, row.PartitionKey)
			if err != nil {
				return CookieSnapshot{}, err
			}
			entry.PartitionKey = &value
		}
		if row.Flags&16 != 0 {
			value, err := projectTimestamp(row.Expiry)
			if err != nil {
				return CookieSnapshot{}, err
			}
			entry.ExpiresAt = &value
		}
		snapshot.Entries[index] = entry
	}
	return snapshot, nil
}

func projectAltSvc(result stateResult) (AltSvcSnapshot, error) {
	snapshot := AltSvcSnapshot{Enabled: result.value.Enabled == 1, Entries: make([]AltSvcEntry, len(result.alternatives))}
	for index, row := range result.alternatives {
		if row.Port > 65535 {
			return AltSvcSnapshot{}, &Error{Kind: "native_abi"}
		}
		origin, err := stateString(result.arena, row.Origin)
		if err != nil {
			return AltSvcSnapshot{}, err
		}
		host, err := stateString(result.arena, row.Host)
		if err != nil {
			return AltSvcSnapshot{}, err
		}
		expiry, err := projectTimestamp(row.Expiry)
		if err != nil {
			return AltSvcSnapshot{}, err
		}
		snapshot.Entries[index] = AltSvcEntry{Origin: origin, Host: host, Port: uint16(row.Port), ExpiresAt: expiry}
	}
	return snapshot, nil
}
