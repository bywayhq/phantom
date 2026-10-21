package phantom

import (
	"encoding/json"
	"runtime"
)

// SetCookie updates the native bounded jar using a Set-Cookie field.
func (c *Client) SetCookie(url, value string) error {
	_, err := dispatch(map[string]any{"kind": "cookie_set", "client": c.id.Load(), "url": url, "value": value}, nil)
	runtime.KeepAlive(c)
	return err
}

// CookiesForURL returns the native jar's request Cookie value, or an empty string.
func (c *Client) CookiesForURL(url string) (string, error) {
	value, err := dispatch(map[string]any{"kind": "cookie_get", "client": c.id.Load(), "url": url}, nil)
	runtime.KeepAlive(c)
	if err != nil {
		return "", err
	}
	var result struct {
		Cookie *string `json:"cookie"`
	}
	if json.Unmarshal(value, &result) != nil {
		return "", &Error{Kind: "native_abi"}
	}
	if result.Cookie == nil {
		return "", nil
	}
	return *result.Cookie, nil
}

// ClearCookies clears this client's jar.
func (c *Client) ClearCookies() error {
	err := control("cookie_clear", "client", c.id.Load())
	runtime.KeepAlive(c)
	return err
}
