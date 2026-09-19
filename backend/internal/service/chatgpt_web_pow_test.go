//go:build unit

package service

import (
	"crypto/sha3"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func chatGPTWebFixedPowConfig() []any {
	return []any{
		3000,
		"Mon Sep 01 2026 00:00:00 GMT-0500 (Eastern Standard Time)",
		4294705152,
		1,
		"mozilla",
		"https://chatgpt.com/backend-api/sentinel/sdk.js",
		"c/abcdef/_",
		"en-US",
		"en-US,es-US,en,es",
		1,
		"webdriver\u2212false",
		"location",
		"window",
		1234.5,
		"00000000-0000-0000-0000-000000000000",
		"",
		8,
		1700000000000.5,
		0, 0, 0, 0, 0, 0,
		0,
	}
}

// 服务端就是用同一关系校验 PoW：sha3_512(seed + base64(payload)) 前缀需命中 difficulty。
func TestChatGPTWebPowGenerateSatisfiesDifficulty(t *testing.T) {
	seed := "0.559779845730002"
	difficulty := "0fffff"
	answer, solved := chatGPTWebPowGenerate(seed, difficulty, chatGPTWebFixedPowConfig(), 500000)
	require.True(t, solved)
	require.NotEmpty(t, answer)

	digest := sha3.New512()
	_, _ = digest.Write([]byte(seed))
	_, _ = digest.Write([]byte(answer))
	target, err := hex.DecodeString(difficulty)
	require.NoError(t, err)
	require.LessOrEqual(t, string(digest.Sum(nil)[:len(target)]), string(target))

	payload, err := base64.StdEncoding.DecodeString(answer)
	require.NoError(t, err)
	var decoded []any
	require.NoError(t, json.Unmarshal(payload, &decoded))
	require.Len(t, decoded, 25)
}

func TestChatGPTWebPowGenerateRejectsBadDifficulty(t *testing.T) {
	_, solved := chatGPTWebPowGenerate("seed", "zz", chatGPTWebFixedPowConfig(), 10)
	require.False(t, solved)
}

// 与参考实现（Python）对拍的固定向量：config/seed/difficulty 相同时产物必须逐字节一致。
func TestChatGPTWebPowMatchesReferenceVector(t *testing.T) {
	answer, solved := chatGPTWebPowGenerate("0.559779845730002", "0fffff", chatGPTWebFixedPowConfig(), 500000)
	require.True(t, solved)
	require.Equal(t, "WzMwMDAsIk1vbiBTZXAgMDEgMjAyNiAwMDowMDowMCBHTVQtMDUwMCAoRWFzdGVybiBTdGFuZGFyZCBUaW1lKSIsNDI5NDcwNTE1MiwwLCJtb3ppbGxhIiwiaHR0cHM6Ly9jaGF0Z3B0LmNvbS9iYWNrZW5kLWFwaS9zZW50aW5lbC9zZGsuanMiLCJjL2FiY2RlZi9fIiwiZW4tVVMiLCJlbi1VUyxlcy1VUyxlbixlcyIsMCwid2ViZHJpdmVy4oiSZmFsc2UiLCJsb2NhdGlvbiIsIndpbmRvdyIsMTIzNC41LCIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDAiLCIiLDgsMTcwMDAwMDAwMDAwMC41LDAsMCwwLDAsMCwwLDBd", answer)
}

func TestChatGPTWebBuildRequirementsTokenShape(t *testing.T) {
	token := chatGPTWebBuildRequirementsToken("mozilla", nil, "c/abcdef/_")
	require.True(t, strings.HasPrefix(token, "gAAAAAC"))
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(token, "gAAAAAC"))
	require.NoError(t, err)
	var decoded []any
	require.NoError(t, json.Unmarshal(raw, &decoded))
	require.Len(t, decoded, 25)
	require.Equal(t, "c/abcdef/_", decoded[6])
}

func TestChatGPTWebBuildProofTokenPrefix(t *testing.T) {
	token, err := chatGPTWebBuildProofToken("0.559779845730002", "0fffff", "mozilla", nil, "")
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(token, "gAAAAAB"))
}

func TestParseChatGPTWebPowResources(t *testing.T) {
	html := `<html data-build="prod-abc"><head>` +
		`<script src="https://chatgpt.com/c/abcdef/_next/static/chunks/main.js"></script>` +
		`</head></html>`
	sources, dataBuild := parseChatGPTWebPowResources(html)
	require.Len(t, sources, 1)
	require.Equal(t, "c/abcdef/_", dataBuild)

	sources, dataBuild = parseChatGPTWebPowResources(`<html data-build="prod-fallback"><head></head></html>`)
	require.Equal(t, []string{chatGPTWebDefaultPowScript}, sources)
	require.Equal(t, "prod-fallback", dataBuild)
}
