package service

import "net/http"

// Captured from the locally installed standalone Codex CLI 0.163.0 on
// 2026-10-16 (macOS arm64, non-interactive exec with TERM=dumb).
// Its model-provider TLS ClientHello matches the existing CodexCLIProfile.
// Keep this image-only override separate from the configurable text identity.
const oauthImageCodexCLIVersion = "0.163.0"
const oauthImageCodexCLIUserAgent = "codex_exec/" + oauthImageCodexCLIVersion +
	" (Mac OS 15.6.0; arm64) dumb (codex_exec; " + oauthImageCodexCLIVersion + ")"

func applyOAuthImageCodexIdentity(headers http.Header, account *Account) {
	if account == nil || account.Type != AccountTypeOAuth || account.UsesOpenAINativeImageChannel() || account.UsesChatGPTWebImageChannel() || account.IsOpenAIPersonalAccessToken() || account.IsOpenAIAgentIdentity() {
		return
	}
	headers.Set("User-Agent", oauthImageCodexCLIUserAgent)
	headers.Set("Originator", "codex_exec")
	headers.Set("Version", oauthImageCodexCLIVersion)
}
