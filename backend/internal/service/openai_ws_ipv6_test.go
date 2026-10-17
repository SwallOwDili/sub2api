package service

import (
	"github.com/Wei-Shaw/sub2api/internal/pkg/chatgptnetwork"
	"net/http"
	"testing"
)

func TestOpenAIWSChatGPTIPv6Policy(t *testing.T) {
	t.Setenv(chatgptnetwork.EnvIPv6Only, "true")
	d := newDefaultOpenAIWSClientDialer().(*coderOpenAIWSClientDialer)
	for _, proxy := range []string{"http://127.0.0.1:7890", "socks5://127.0.0.1:7890"} {
		client, err := d.proxyHTTPClient(proxy)
		if err != nil {
			t.Fatal(err)
		}
		tr := client.Transport
		defer client.CloseIdleConnections()
		req, _ := http.NewRequest("GET", "https://chatgpt.com/backend-api/codex/responses", nil)
		_, err = tr.RoundTrip(req)
		if (err != nil) != (proxy != "") {
			t.Fatalf("proxy=%s err=%v", proxy, err)
		}
	}
}
