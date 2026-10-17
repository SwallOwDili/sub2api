// Package chatgptnetwork scopes IP-family policy to ChatGPT upstreams.
package chatgptnetwork

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

const EnvIPv6Only = "SUB2API_CHATGPT_IPV6_ONLY"

func isChatGPT(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return host == "chatgpt.com" || strings.HasSuffix(host, ".chatgpt.com")
}

// Apply snapshots startup configuration when constructing a transport. Changing
// the setting requires a restart so existing pooled connections cannot bypass it.
// Proxies are rejected only for ChatGPT: their final address family is unknown.
func Apply(t *http.Transport, configuredProxy bool) {
	value := strings.TrimSpace(os.Getenv(EnvIPv6Only))
	if value == "" {
		return
	}
	enabled, parseErr := strconv.ParseBool(value)
	if parseErr == nil && !enabled {
		return
	}
	applyIPv6(t, configuredProxy, parseErr)
}

func applyIPv6(t *http.Transport, configuredProxy bool, parseErr error) {
	check := func(host string, proxied bool) error {
		if !isChatGPT(host) {
			return nil
		}
		if parseErr != nil {
			return fmt.Errorf("%s must be a boolean", EnvIPv6Only)
		}
		if proxied {
			return fmt.Errorf("%s cannot guarantee IPv6 through a configured proxy", EnvIPv6Only)
		}
		return nil
	}
	originalProxy := t.Proxy
	t.Proxy = func(r *http.Request) (*url.URL, error) {
		var p *url.URL
		var err error
		if originalProxy != nil {
			p, err = originalProxy(r)
		}
		if err != nil {
			return nil, err
		}
		if err = check(r.URL.Hostname(), configuredProxy || p != nil); err != nil {
			return nil, err
		}
		return p, nil
	}
	wrap := func(dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if err = check(host, configuredProxy); err != nil {
				return nil, err
			}
			if isChatGPT(host) {
				network = "tcp6"
			}
			return dial(ctx, network, addr)
		}
	}
	dial := t.DialContext
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	t.DialContext = wrap(dial)
	if t.DialTLSContext != nil {
		t.DialTLSContext = wrap(t.DialTLSContext)
	}
}
