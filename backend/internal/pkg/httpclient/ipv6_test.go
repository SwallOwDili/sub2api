package httpclient

import (
	"github.com/Wei-Shaw/sub2api/internal/pkg/chatgptnetwork"
	"net/http"
	"testing"
)

func TestChatGPTIPv6SharedClientPolicy(t *testing.T) {
	t.Setenv(chatgptnetwork.EnvIPv6Only, "true")
	for _, proxy := range []string{"http://127.0.0.1:7890", "socks5://127.0.0.1:7890"} {
		tr, err := buildTransport(Options{ProxyURL: proxy})
		if err != nil {
			t.Fatal(err)
		}
		defer tr.CloseIdleConnections()
		req, _ := http.NewRequest("GET", "https://chatgpt.com/backend-api/wham/usage", nil)
		_, err = chatgptnetwork.Wrap(tr, true).RoundTrip(req)
		if (err != nil) != (proxy != "") {
			t.Fatalf("proxy=%s err=%v", proxy, err)
		}
	}
}
