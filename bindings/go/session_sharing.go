package phantom

import "runtime"

// SessionSharing selects live state shared by a fork. Its zero value shares
// nothing. Selecting a category does not enable it when the source disabled it.
type SessionSharing struct {
	Cookies     bool `json:"cookies"`
	DNS         bool `json:"dns"`
	ClientHints bool `json:"client_hints"`
	Discovery   bool `json:"discovery"`
	Tickets     bool `json:"tickets"`
}

// Fork preserves settings and protocol with independent pools, admission and
// shutdown. Selected state shares later changes, expiry and clearing. Unselected
// state and learned proxy authentication start empty. Call Close on the new owner.
// A source released by Shutdown cannot be forked; a concurrent shutdown either
// leaves a registered source available to fork or returns client_closed.
func (c *Client) Fork(sharing SessionSharing) (*Client, error) {
	if c == nil || c.id.Load() == 0 {
		return nil, &Error{Kind: "client_closed"}
	}
	defer runtime.KeepAlive(c)
	value, err := dispatch(map[string]any{"kind": "fork_client", "client": c.id.Load(), "sharing": sharing}, nil)
	if err != nil {
		return nil, err
	}
	return clientFromReply(value)
}
