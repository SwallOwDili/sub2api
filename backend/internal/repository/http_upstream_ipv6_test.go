package repository

import (
	"github.com/Wei-Shaw/sub2api/internal/pkg/chatgptnetwork"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	"net/http"
	"net/url"
	"testing"
)

func TestChatGPTIPv6UpstreamTransportCoverage(t *testing.T) {
	t.Setenv(chatgptnetwork.EnvIPv6Only, "true")
	proxy, _ := url.Parse("http://127.0.0.1:7890")
	for _, fingerprint := range []bool{false, true} {
		var tr *http.Transport
		var err error
		if fingerprint {
			tr, err = buildUpstreamTransportWithTLSFingerprint(poolSettings{}, proxy, tlsfingerprint.CodexCLIProfile())
		} else {
			tr, err = buildUpstreamTransport(poolSettings{}, proxy, upstreamProtocolModeOpenAIH2)
		}
		if err != nil {
			t.Fatal(err)
		}
		defer tr.CloseIdleConnections()
		for _, path := range []string{"/backend-api/codex/responses", "/backend-api/f/conversation", "/backend-api/codex/images/generations", "/backend-api/codex/images/edits"} {
			req, _ := http.NewRequest("POST", "https://chatgpt.com"+path, nil)
			if _, err := chatgptnetwork.Wrap(tr, true).RoundTrip(req); err == nil {
				t.Fatalf("missing guard fingerprint=%v path=%s", fingerprint, path)
			}
		}
	}
}
