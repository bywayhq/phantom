package phantom

import (
	"context"
	"encoding/json"
	"runtime"
)

// CloseIdleConnections releases idle connections without interrupting active work.
// TLS tickets, cookies and learned caches remain available.
func (c *Client) CloseIdleConnections(ctx context.Context) error {
	return c.maintain(ctx, "close_idle_connections")
}

// RefreshConnections selects fresh connections for later requests. Existing work
// can finish on old connections. It retains tickets and learned state, and does
// not wait for old drivers to stop. Cancellation can leave some pools unvisited.
func (c *Client) RefreshConnections(ctx context.Context) error {
	return c.maintain(ctx, "refresh_connections")
}

func (c *Client) maintain(ctx context.Context, action string) error {
	if ctx == nil {
		return &Error{Kind: "invalid_context"}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.closing.Load() || c.id.Load() == 0 {
		return &Error{Kind: "client_closed"}
	}
	err := perform(ctx, map[string]any{"kind": "maintain", "client": c.id.Load(), "action": action}, nil, func(completion) error { return nil })
	runtime.KeepAlive(c)
	return err
}

// ClearDNSCache forgets cached host addresses. In-flight lookups still answer
// their existing waiters but cannot repopulate the cleared cache.
func (c *Client) ClearDNSCache() error { return c.clearState("dns") }

// ClearClientHints forgets learned Accept-CH preferences.
func (c *Client) ClearClientHints() error { return c.clearState("client_hints") }

// ClearAltSvc forgets learned alternatives and their racing history.
func (c *Client) ClearAltSvc() error { return c.clearState("alt_svc") }

// ClearAltSvcRacingHistory forgets RTT samples and client-local QUIC success.
func (c *Client) ClearAltSvcRacingHistory() error {
	return c.clearState("alt_svc_racing_history")
}

func (c *Client) clearState(category string) error {
	_, err := c.clearStateValue(category)
	return err
}

func (c *Client) clearStateValue(category string) (json.RawMessage, error) {
	if c.id.Load() == 0 {
		return nil, &Error{Kind: "client_closed"}
	}
	value, err := dispatch(map[string]any{"kind": "clear_state", "client": c.id.Load(), "category": category}, nil)
	runtime.KeepAlive(c)
	return value, err
}

// ClearSessionTickets removes retained origin/proxy TCP and QUIC TLS tickets.
// Existing connections keep working. Older handshakes cannot restore tickets.
// It returns the number removed from caches and pending library callbacks.
func (c *Client) ClearSessionTickets() (uint64, error) {
	value, err := c.clearStateValue("session_tickets")
	if err != nil {
		return 0, err
	}
	var result struct {
		Removed uint64 `json:"removed"`
	}
	if json.Unmarshal(value, &result) != nil {
		return 0, &Error{Kind: "native_abi"}
	}
	return result.Removed, nil
}
