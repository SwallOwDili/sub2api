package chatgptnetwork

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"testing"
)

func TestPolicyScopeAndDialers(t *testing.T) {
	for _, value := range []string{"", "false", "true", "bad"} {
		for _, host := range []string{"chatgpt.com", "CHATGPT.COM.", "ws.chatgpt.com", "api.anthropic.com", "api.openai.com", "evilchatgpt.com", "chatgpt.com.evil.test"} {
			for _, proxied := range []bool{false, true} {
				t.Run(value+host+map[bool]string{true: "proxy", false: "direct"}[proxied], func(t *testing.T) {
					t.Setenv(EnvIPv6Only, value)
					called := false
					got := ""
					sentinel := errors.New("dial observed")
					dial := func(_ context.Context, network, addr string) (net.Conn, error) {
						called = true
						got = network
						return nil, sentinel
					}
					tr := &http.Transport{DialContext: dial, DialTLSContext: dial}
					Apply(tr, proxied)
					for _, fn := range []func(context.Context, string, string) (net.Conn, error){tr.DialContext, tr.DialTLSContext} {
						called = false
						_, err := fn(context.Background(), "tcp", net.JoinHostPort(host, "443"))
						blocked := isChatGPT(host) && (value == "bad" || (value == "true" && proxied))
						if blocked {
							if called || err == nil {
								t.Fatal("must fail before dialing")
							}
							continue
						}
						if !called || !errors.Is(err, sentinel) {
							t.Fatal("dial not preserved")
						}
						want := "tcp"
						if value == "true" && isChatGPT(host) {
							want = "tcp6"
						}
						if got != want {
							t.Fatalf("got %s want %s", got, want)
						}
					}
				})
			}
		}
	}
}

func TestHTTPProxyGuard(t *testing.T) {
	t.Setenv(EnvIPv6Only, "true")
	p, _ := url.Parse("http://127.0.0.1:1234")
	tr := &http.Transport{Proxy: http.ProxyURL(p)}
	Apply(tr, false)
	for _, host := range []string{"chatgpt.com", "api.anthropic.com"} {
		req, _ := http.NewRequest("GET", "https://"+host, nil)
		got, err := tr.Proxy(req)
		if host == "chatgpt.com" {
			if err == nil {
				t.Fatal("proxy not blocked")
			}
		} else if err != nil || got != p {
			t.Fatal("other platform affected")
		}
	}
}

func TestIPv6SocketAndNoIPv4Fallback(t *testing.T) {
	t.Setenv(EnvIPv6Only, "true")
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer ln.Close()
	tr := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, ln.Addr().String())
	}}
	Apply(tr, false)
	conn, err := tr.DialContext(context.Background(), "tcp", "chatgpt.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if conn.RemoteAddr().(*net.TCPAddr).IP.To4() != nil {
		t.Fatal("not IPv6")
	}
	tr = &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:1")
	}}
	Apply(tr, false)
	if conn, err = tr.DialContext(context.Background(), "tcp", "chatgpt.com:443"); err == nil {
		conn.Close()
		t.Fatal("unexpected IPv4 fallback")
	}
}
