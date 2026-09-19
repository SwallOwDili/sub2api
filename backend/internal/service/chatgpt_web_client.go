package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	"github.com/google/uuid"
	"github.com/tidwall/gjson"
)

// ChatGPT Web 网页链路客户端：用账号的 access_token 驱动 chatgpt.com 官网对话接口。
// 网页图片生成消耗的是网页侧 image_gen 额度，与 Codex/Responses 额度相互独立。
//
// 链路：GET / 取 sentinel 资源 -> chat-requirements prepare/finalize 拿 sentinel token
// -> f/conversation/prepare 拿 conduit token -> f/conversation SSE 拿图片指针
// -> files/{id}/download 取下载地址 -> 下载图片字节。

const (
	chatGPTWebBaseURL                  = "https://chatgpt.com"
	chatGPTWebImageHint                = "picture_v2"
	chatGPTWebDefaultUpstreamModel     = "auto"
	chatGPTWebDefaultClientVersion     = "prod-a194cd50d4416d3c0b47c740f206b12ce60f5887"
	chatGPTWebDefaultClientBuildNumber = "6708908"
	chatGPTWebDefaultUserAgent         = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0"
	chatGPTWebDefaultSecChUA         = `"Microsoft Edge";v="143", "Chromium";v="143", "Not A(Brand";v="24"`
	chatGPTWebDefaultSecChUAPlatform = `"Windows"`
	chatGPTWebPollInterval           = 2 * time.Second
	chatGPTWebPollTimeout            = 120 * time.Second
	chatGPTWebDownloadRetry          = 8
)

type chatGPTWebDevice struct {
	UserAgent string
	DeviceID  string
	SessionID string
}

func (d chatGPTWebDevice) withDefaults() chatGPTWebDevice {
	if strings.TrimSpace(d.UserAgent) == "" {
		d.UserAgent = chatGPTWebDefaultUserAgent
	}
	if strings.TrimSpace(d.DeviceID) == "" {
		d.DeviceID = uuid.NewString()
	}
	if strings.TrimSpace(d.SessionID) == "" {
		d.SessionID = uuid.NewString()
	}
	return d
}

type chatGPTWebSentinel struct {
	Token      string
	ProofToken string
	SOToken    string
}

type chatGPTWebSession struct {
	transport   HTTPUpstream
	accountID   int64
	concurrency int
	proxyURL    string
	baseURL     string
	accessToken string
	device      chatGPTWebDevice
	// tlsProfile 非空时启用 TLS 指纹伪装。chatgpt.com 前置 Cloudflare 会对非常规
	// TLS 指纹直接下发 403 challenge，普通 Go 客户端拿不到 backend-api。
	tlsProfile *tlsfingerprint.Profile
}

// chatGPTWebTLSFingerprintProfile 是网页链路实测可用的 TLS 指纹。
//
// 同 IP、同时刻对照实验：项目默认的 Node.js 风格手工指纹 0/5 次通过，
// 全部被 Cloudflare 下发 403 cf-mitigated: challenge；换成 uTLS 内置 Chrome
// ClientHello 后 5/5 通过。因此这里必须用 Chrome 预设，而不是手工拼扩展。
func chatGPTWebTLSFingerprintProfile() *tlsfingerprint.Profile {
	return &tlsfingerprint.Profile{
		Name:          "chatgpt-web-chrome",
		Preset:        tlsfingerprint.PresetChrome,
		ALPNProtocols: []string{"http/1.1"},
	}
}

func newChatGPTWebSession(
	transport HTTPUpstream,
	account *Account,
	accessToken string,
	device chatGPTWebDevice,
) *chatGPTWebSession {
	proxyURL := ""
	if account != nil && account.ProxyID != nil && account.Proxy != nil {
		proxyURL = account.Proxy.URL()
	}
	session := &chatGPTWebSession{
		transport:   transport,
		proxyURL:    proxyURL,
		baseURL:     chatGPTWebBaseURL,
		accessToken: strings.TrimSpace(accessToken),
		device:      device.withDefaults(),
		tlsProfile:  chatGPTWebTLSFingerprintProfile(),
	}
	if account != nil {
		session.accountID = account.ID
		session.concurrency = account.Concurrency
	}
	return session
}

func (s *chatGPTWebSession) do(req *http.Request) (*http.Response, error) {
	if s.tlsProfile != nil {
		return s.transport.DoWithTLS(req, s.proxyURL, s.accountID, s.concurrency, s.tlsProfile)
	}
	return s.transport.Do(req, s.proxyURL, s.accountID, s.concurrency)
}

func (s *chatGPTWebSession) defaultHeaders() map[string]string {
	headers := map[string]string{
		"User-Agent":                 s.device.UserAgent,
		"Origin":                     s.baseURL,
		"Referer":                    s.baseURL + "/",
		"Accept-Language":            "zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7",
		"Cache-Control":              "no-cache",
		"Pragma":                     "no-cache",
		"Priority":                   "u=1, i",
		"Sec-Ch-Ua":                  chatGPTWebDefaultSecChUA,
		"Sec-Ch-Ua-Arch":             `"x86"`,
		"Sec-Ch-Ua-Bitness":          `"64"`,
		"Sec-Ch-Ua-Mobile":           "?0",
		"Sec-Ch-Ua-Model":            `""`,
		"Sec-Ch-Ua-Platform":         chatGPTWebDefaultSecChUAPlatform,
		"Sec-Ch-Ua-Platform-Version": `"19.0.0"`,
		"Sec-Fetch-Dest":             "empty",
		"Sec-Fetch-Mode":             "cors",
		"Sec-Fetch-Site":             "same-origin",
		"OAI-Device-Id":              s.device.DeviceID,
		"OAI-Session-Id":             s.device.SessionID,
		"OAI-Language":               "zh-CN",
		"OAI-Client-Version":         chatGPTWebDefaultClientVersion,
		"OAI-Client-Build-Number":    chatGPTWebDefaultClientBuildNumber,
	}
	if token := strings.TrimSpace(s.accessToken); token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	return headers
}

func (s *chatGPTWebSession) doJSON(
	ctx context.Context,
	method string,
	path string,
	body any,
	extraHeaders map[string]string,
) (*http.Response, error) {
	var payload []byte
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encode chatgpt web request: %w", err)
		}
		payload = encoded
	}
	return s.doChatGPTRequest(ctx, method, path, payload, extraHeaders)
}

// doChatGPTRequest sends an authenticated first-party ChatGPT request. Redirects
// are disabled because custom device headers must never cross an origin boundary.
func (s *chatGPTWebSession) doChatGPTRequest(
	ctx context.Context,
	method string,
	path string,
	payload []byte,
	extraHeaders map[string]string,
) (*http.Response, error) {
	return s.doChatGPTURLRequest(ctx, method, s.baseURL+path, path, payload, extraHeaders)
}

func (s *chatGPTWebSession) doChatGPTURLRequest(
	ctx context.Context,
	method string,
	target string,
	path string,
	payload []byte,
	extraHeaders map[string]string,
) (*http.Response, error) {
	if !isChatGPTWebFirstPartyURL(target) {
		return nil, fmt.Errorf("chatgpt web request target is not first-party")
	}
	headers := s.defaultHeaders()
	if path != "" {
		headers["X-OpenAI-Target-Path"] = path
		headers["X-OpenAI-Target-Route"] = path
	}
	for key, value := range extraHeaders {
		headers[key] = value
	}
	var reader io.Reader
	if payload != nil {
		reader = bytes.NewReader(payload)
		if _, exists := headers["Content-Type"]; !exists {
			headers["Content-Type"] = "application/json"
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, err
	}
	for key, value := range headers {
		if value != "" {
			req.Header.Set(key, value)
		}
	}
	req = req.WithContext(WithHTTPUpstreamRedirectsDisabled(WithHTTPUpstreamProfile(req.Context(), HTTPUpstreamProfileOpenAI)))
	return s.do(req)
}

// doSignedAssetRequest handles pre-signed object-storage URLs. These URLs are
// allowed to be cross-origin, but must never receive ChatGPT credentials.
func (s *chatGPTWebSession) doSignedAssetRequest(
	ctx context.Context,
	method string,
	target string,
	payload []byte,
	headers map[string]string,
) (*http.Response, error) {
	parsed, err := url.Parse(target)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || strings.TrimSpace(parsed.Hostname()) == "" {
		return nil, fmt.Errorf("invalid signed asset url")
	}
	req, err := http.NewRequestWithContext(WithHTTPUpstreamPublicHostsOnly(ctx), method, target, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	for key, value := range headers {
		if value != "" {
			req.Header.Set(key, value)
		}
	}
	return s.transport.Do(req, s.proxyURL, s.accountID, s.concurrency)
}

func isChatGPTWebFirstPartyURL(target string) bool {
	parsed, err := url.Parse(target)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") {
		return false
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	return host == "chatgpt.com" || strings.HasSuffix(host, ".chatgpt.com")
}

// bootstrap 抓首页 HTML，供 PoW 指纹使用 sentinel sdk 的真实地址与构建号。
func (s *chatGPTWebSession) bootstrap(ctx context.Context) ([]string, string) {
	response, err := s.doJSON(ctx, http.MethodGet, "/", nil, map[string]string{
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	})
	if err != nil {
		return nil, ""
	}
	defer func() { _ = response.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, ""
	}
	return parseChatGPTWebPowResources(string(raw))
}

// fetchSentinel 走完 prepare -> PoW/Turnstile -> finalize，拿到四件套 token。
func (s *chatGPTWebSession) fetchSentinel(ctx context.Context) (*chatGPTWebSentinel, error) {
	scriptSources, dataBuild := s.bootstrap(ctx)
	requirementsToken := chatGPTWebBuildRequirementsToken(s.device.UserAgent, scriptSources, dataBuild)

	preparePath := "/backend-api/sentinel/chat-requirements/prepare"
	prepareResp, err := s.doJSON(ctx, http.MethodPost, preparePath, map[string]any{"p": requirementsToken}, nil)
	if err != nil {
		return nil, fmt.Errorf("chatgpt web sentinel prepare: %w", err)
	}
	prepareBody, err := readChatGPTWebBody(prepareResp)
	if err != nil {
		return nil, err
	}
	if gjson.GetBytes(prepareBody, "arkose.required").Bool() {
		return nil, fmt.Errorf("chatgpt web sentinel requires arkose challenge")
	}

	proofToken := ""
	if gjson.GetBytes(prepareBody, "proofofwork.required").Bool() {
		proofToken, err = chatGPTWebBuildProofToken(
			gjson.GetBytes(prepareBody, "proofofwork.seed").String(),
			gjson.GetBytes(prepareBody, "proofofwork.difficulty").String(),
			s.device.UserAgent,
			scriptSources,
			dataBuild,
		)
		if err != nil {
			return nil, err
		}
	}

	// Turnstile 不实现：当前 dx 的指令表已换成动态槽位形式，公开参考实现（chatgpt2api
	// utils/turnstile.py）对同一份真实样本同样产出空 token。实测 finalize 不携带
	// OpenAI-Sentinel-Turnstile-Token 仍会签发 sentinel token，因此这里不尝试解算，
	// 也不为此引入浏览器或打码依赖。
	finalizePath := "/backend-api/sentinel/chat-requirements/finalize"
	finalizeResp, err := s.doJSON(ctx, http.MethodPost, finalizePath, map[string]any{
		"prepare_token": gjson.GetBytes(prepareBody, "prepare_token").String(),
		"proof_token":   proofToken,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("chatgpt web sentinel finalize: %w", err)
	}
	finalizeBody, err := readChatGPTWebBody(finalizeResp)
	if err != nil {
		return nil, err
	}
	token := strings.TrimSpace(gjson.GetBytes(finalizeBody, "token").String())
	if token == "" {
		return nil, fmt.Errorf("chatgpt web sentinel returned empty token")
	}
	return &chatGPTWebSentinel{
		Token:      token,
		ProofToken: proofToken,
		SOToken:    strings.TrimSpace(gjson.GetBytes(finalizeBody, "so_token").String()),
	}, nil
}

// chatGPTWebUpstreamError 保留上游状态码，供上层决定换号/冷却。
type chatGPTWebUpstreamError struct {
	StatusCode int
	Message    string
	Body       []byte
	// Challenge 表示命中 Cloudflare 挑战页（HTML 拦截页），换号无意义。
	Challenge bool
}

func (e *chatGPTWebUpstreamError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

func isChatGPTWebChallengePage(response *http.Response, body []byte) bool {
	if response == nil {
		return false
	}
	if strings.TrimSpace(response.Header.Get("cf-mitigated")) != "" {
		return true
	}
	trimmed := strings.TrimSpace(string(body))
	return strings.HasPrefix(trimmed, "<html") || strings.HasPrefix(trimmed, "<!DOCTYPE")
}

type chatGPTWebFailureKind int

const (
	chatGPTWebFailureNone chatGPTWebFailureKind = iota
	chatGPTWebFailureAuth
	chatGPTWebFailureQuota
	chatGPTWebFailureChallenge
	chatGPTWebFailureTransient
)

// classifyChatGPTWebFailure 只依据 HTTP 状态码与"是否为拦截页"归因，不猜文案。
func classifyChatGPTWebFailure(statusCode int, challenge bool) chatGPTWebFailureKind {
	switch {
	case challenge:
		return chatGPTWebFailureChallenge
	case statusCode == http.StatusUnauthorized:
		return chatGPTWebFailureAuth
	case statusCode == http.StatusForbidden:
		return chatGPTWebFailureAuth
	case statusCode == http.StatusTooManyRequests, statusCode == http.StatusPaymentRequired:
		return chatGPTWebFailureQuota
	case statusCode >= 500:
		return chatGPTWebFailureTransient
	default:
		return chatGPTWebFailureNone
	}
}

// clientStatusCode 决定对外暴露的状态码：账号侧的鉴权/拦截问题统一收敛成 502，
// 只有真正的限额语义才回 429，避免把"某个账号凭证失效"误报成客户端错误。
func (e *chatGPTWebUpstreamError) clientStatusCode() int {
	if e == nil {
		return http.StatusBadGateway
	}
	// 账号侧问题（鉴权失效、限额、Cloudflare 拦截）对客户端都不该表现为 401/403：
	// 只有真正的限额语义回 429 便于重试，其余统一收敛成 502。
	if !e.Challenge && (e.StatusCode == http.StatusTooManyRequests || e.StatusCode == http.StatusPaymentRequired) {
		return http.StatusTooManyRequests
	}
	return http.StatusBadGateway
}

func newChatGPTWebResponseError(response *http.Response, fallback string, body []byte) *chatGPTWebUpstreamError {
	statusCode := 0
	if response != nil {
		statusCode = response.StatusCode
	}
	message := fmt.Sprintf("%s: HTTP %d: %s", fallback, statusCode, truncateChatGPTWebText(string(body), 200))
	return &chatGPTWebUpstreamError{
		StatusCode: statusCode,
		Message:    message,
		Body:       body,
		Challenge:  isChatGPTWebChallengePage(response, body),
	}
}

func readChatGPTWebBody(response *http.Response) ([]byte, error) {
	defer func() { _ = response.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 400 {
		return nil, newChatGPTWebResponseError(response, "chatgpt web upstream", raw)
	}
	return raw, nil
}

func truncateChatGPTWebText(text string, limit int) string {
	trimmed := strings.TrimSpace(text)
	if len(trimmed) <= limit {
		return trimmed
	}
	return trimmed[:limit] + "..."
}

func (s *chatGPTWebSession) sentinelHeaders(path string, sentinel *chatGPTWebSentinel, extra map[string]string) map[string]string {
	headers := map[string]string{
		"X-OpenAI-Target-Path":  path,
		"X-OpenAI-Target-Route": path,
	}
	if sentinel != nil {
		if sentinel.Token != "" {
			headers["OpenAI-Sentinel-Chat-Requirements-Token"] = sentinel.Token
		}
		if sentinel.ProofToken != "" {
			headers["OpenAI-Sentinel-Proof-Token"] = sentinel.ProofToken
		}
		if sentinel.SOToken != "" {
			headers["OpenAI-Sentinel-SO-Token"] = sentinel.SOToken
		}
	}
	for key, value := range extra {
		headers[key] = value
	}
	return headers
}

// imageModelSettings 把对外图片模型名映射成网页侧 upstream model。
// gpt-image-2 走账号配置的网页上游模型；codex 专用别名不在此链路。
func chatGPTWebImageModelSettings(requestModel, upstreamModel string) string {
	model := strings.TrimSpace(requestModel)
	if model == "" || strings.EqualFold(model, "dall-e-3") || strings.EqualFold(model, "dall-e-2") {
		return chatGPTWebDefaultUpstreamModel
	}
	if mapped := strings.TrimSpace(upstreamModel); mapped != "" {
		return mapped
	}
	if strings.HasPrefix(model, "gpt-image") {
		return chatGPTWebDefaultUpstreamModel
	}
	return model
}

// chatGPTWebReference 是网页端可引用的上传文件。
type chatGPTWebReference struct {
	FileID    string
	FileName  string
	MIMEType  string
	SizeBytes int
	Width     int
	Height    int
}

func chatGPTWebMultimodalContent(prompt string, references []*chatGPTWebReference) map[string]any {
	parts := make([]any, 0, len(references)+1)
	for _, reference := range references {
		if reference == nil || reference.FileID == "" {
			continue
		}
		parts = append(parts, map[string]any{
			"content_type":  "image_asset_pointer",
			"asset_pointer": "file-service://" + reference.FileID,
			"width":         reference.Width,
			"height":        reference.Height,
			"size_bytes":    reference.SizeBytes,
		})
	}
	parts = append(parts, prompt)
	return map[string]any{"content_type": "multimodal_text", "parts": parts}
}

func chatGPTWebAttachmentMetadata(references []*chatGPTWebReference) []any {
	attachments := make([]any, 0, len(references))
	for _, reference := range references {
		if reference == nil || reference.FileID == "" {
			continue
		}
		attachments = append(attachments, map[string]any{
			"id":       reference.FileID,
			"mimeType": reference.MIMEType,
			"name":     reference.FileName,
			"size":     reference.SizeBytes,
			"width":    reference.Width,
			"height":   reference.Height,
		})
	}
	return attachments
}

// uploadImage 把参考图交给网页端文件接口，返回 conversation 可引用的 file-service id。
// chatGPTWebImageDimensions 从图片字节解析宽高；解析失败时返回 0（网页端可接受）。
func chatGPTWebImageDimensions(data []byte) (int, int) {
	config, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return 0, 0
	}
	return config.Width, config.Height
}

// decodeChatGPTWebReferenceDataURL decodes an inline reference image locally.
func decodeChatGPTWebReferenceDataURL(raw string) ([]byte, string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, "", fmt.Errorf("chatgpt web reference image is empty")
	}
	if !strings.HasPrefix(strings.ToLower(trimmed), "data:") {
		return nil, "", fmt.Errorf("chatgpt web reference is not a data url")
	}
	comma := strings.Index(trimmed, ",")
	if comma < 0 {
		return nil, "", fmt.Errorf("chatgpt web reference data url is malformed")
	}
	mimeType := "image/png"
	meta := trimmed[len("data:"):comma]
	if index := strings.Index(meta, ";"); index >= 0 {
		meta = meta[:index]
	}
	if strings.TrimSpace(meta) != "" {
		mimeType = strings.TrimSpace(meta)
	}
	data, err := base64.StdEncoding.DecodeString(trimmed[comma+1:])
	if err != nil {
		return nil, "", fmt.Errorf("decode chatgpt web reference data url: %w", err)
	}
	if !strings.HasPrefix(strings.ToLower(mimeType), "image/") {
		return nil, "", fmt.Errorf("chatgpt web reference data url is not an image")
	}
	if !isBackfillImageContent(data) {
		return nil, "", fmt.Errorf("chatgpt web reference data is not an allowed image format")
	}
	return data, detectedImageContentType(data), nil
}

// collectReferences sends uploads and validated reference bytes to the ChatGPT
// files API. URL fetching is injected so the gateway can enforce public-host
// policy without ever exposing the web session's credentials.
func (s *chatGPTWebSession) collectReferences(
	ctx context.Context,
	parsed *OpenAIImagesRequest,
	fetchPublicURL func(context.Context, string) ([]byte, string, error),
) ([]*chatGPTWebReference, error) {
	if parsed == nil {
		return nil, nil
	}
	references := make([]*chatGPTWebReference, 0, len(parsed.Uploads)+len(parsed.InputImageURLs))
	for _, upload := range parsed.Uploads {
		width, height := upload.Width, upload.Height
		if width == 0 || height == 0 {
			width, height = chatGPTWebImageDimensions(upload.Data)
		}
		reference, err := s.uploadImage(ctx, upload.FileName, upload.ContentType, upload.Data, width, height)
		if err != nil {
			return nil, err
		}
		references = append(references, reference)
	}
	for _, rawURL := range parsed.InputImageURLs {
		if strings.TrimSpace(rawURL) == "" {
			continue
		}
		var (
			data     []byte
			mimeType string
			err      error
		)
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(rawURL)), "data:") {
			data, mimeType, err = decodeChatGPTWebReferenceDataURL(rawURL)
		} else if fetchPublicURL != nil {
			data, mimeType, err = fetchPublicURL(ctx, rawURL)
		} else {
			err = fmt.Errorf("chatgpt web public reference fetcher is not configured")
		}
		if err != nil {
			return nil, err
		}
		width, height := chatGPTWebImageDimensions(data)
		fileName := "image." + strings.TrimPrefix(mimeType, "image/")
		reference, err := s.uploadImage(ctx, fileName, mimeType, data, width, height)
		if err != nil {
			return nil, err
		}
		references = append(references, reference)
	}
	return references, nil
}

func (s *chatGPTWebSession) uploadImage(
	ctx context.Context,
	fileName string,
	mimeType string,
	data []byte,
	width int,
	height int,
) (*chatGPTWebReference, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("chatgpt web image upload is empty")
	}
	if strings.TrimSpace(fileName) == "" {
		fileName = "image.png"
	}
	if strings.TrimSpace(mimeType) == "" {
		mimeType = http.DetectContentType(data)
	}
	path := "/backend-api/files"
	response, err := s.doJSON(ctx, http.MethodPost, path, map[string]any{
		"file_name": fileName,
		"file_size": len(data),
		"use_case":  "multimodal",
		"width":     width,
		"height":    height,
	}, map[string]string{"Accept": "application/json"})
	if err != nil {
		return nil, fmt.Errorf("chatgpt web image upload init: %w", err)
	}
	body, err := readChatGPTWebBody(response)
	if err != nil {
		return nil, err
	}
	fileID := strings.TrimSpace(gjson.GetBytes(body, "file_id").String())
	uploadURL := strings.TrimSpace(gjson.GetBytes(body, "upload_url").String())
	if fileID == "" || uploadURL == "" {
		return nil, fmt.Errorf("chatgpt web image upload init returned no file id")
	}

	putResponse, err := s.doSignedAssetRequest(ctx, http.MethodPut, uploadURL, data, map[string]string{
		"Content-Type":    mimeType,
		"x-ms-blob-type":  "BlockBlob",
		"x-ms-version":    "2020-04-08",
		"Accept":          "application/json, text/plain, */*",
		"Accept-Language": "en-US,en;q=0.8",
	})
	if err != nil {
		return nil, fmt.Errorf("chatgpt web image upload: %w", err)
	}
	if _, err := readChatGPTWebBody(putResponse); err != nil {
		return nil, err
	}

	confirmPath := "/backend-api/files/" + fileID + "/uploaded"
	confirmResponse, err := s.doJSON(ctx, http.MethodPost, confirmPath, map[string]any{}, map[string]string{"Accept": "application/json"})
	if err != nil {
		return nil, fmt.Errorf("chatgpt web image upload confirm: %w", err)
	}
	if _, err := readChatGPTWebBody(confirmResponse); err != nil {
		return nil, err
	}
	return &chatGPTWebReference{
		FileID:    fileID,
		FileName:  fileName,
		MIMEType:  mimeType,
		SizeBytes: len(data),
		Width:     width,
		Height:    height,
	}, nil
}

func (s *chatGPTWebSession) prepareImageConversation(
	ctx context.Context,
	prompt string,
	sentinel *chatGPTWebSentinel,
	upstreamModel string,
	references []*chatGPTWebReference,
) (string, error) {
	// Image generations must not create persistent ChatGPT sidebar conversations.
	path := "/backend-api/f/conversation/prepare"
	partialContent := map[string]any{"content_type": "text", "parts": []any{prompt}}
	if len(references) > 0 {
		partialContent = chatGPTWebMultimodalContent(prompt, references)
	}
	payload := map[string]any{
		"action":                "next",
		"fork_from_shared_post": false,
		"parent_message_id":     uuid.NewString(),
		"model":                 upstreamModel,
		"client_prepare_state":  "success",
		"timezone_offset_min":   -480,
		"timezone":              "Asia/Shanghai",
		"conversation_mode":     map[string]any{"kind": "primary_assistant"},
		"system_hints":          []string{chatGPTWebImageHint},
		"partial_query": map[string]any{
			"id":      uuid.NewString(),
			"author":  map[string]any{"role": "user"},
			"content": partialContent,
		},
		"supports_buffering":       true,
		"supported_encodings":      []string{"v1"},
		"client_contextual_info":   map[string]any{"app_name": "chatgpt.com"},
		"enable_message_followups": true,
	}
	response, err := s.doJSON(ctx, http.MethodPost, path, payload, s.sentinelHeaders(path, sentinel, nil))
	if err != nil {
		return "", fmt.Errorf("chatgpt web image prepare: %w", err)
	}
	body, err := readChatGPTWebBody(response)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(gjson.GetBytes(body, "conduit_token").String()), nil
}

func (s *chatGPTWebSession) startImageGeneration(
	ctx context.Context,
	prompt string,
	sentinel *chatGPTWebSentinel,
	conduitToken string,
	upstreamModel string,
	references []*chatGPTWebReference,
) (*http.Response, error) {
	path := "/backend-api/f/conversation"
	messageContent := map[string]any{"content_type": "text", "parts": []any{prompt}}
	messagesMetadata := map[string]any{
		"developer_mode_connector_ids": []any{},
		"selected_github_repos":        []any{},
		"selected_all_github_repos":    false,
		"system_hints":                 []string{chatGPTWebImageHint},
		"serialization_metadata":       map[string]any{"custom_symbol_offsets": []any{}},
	}
	if len(references) > 0 {
		messageContent = chatGPTWebMultimodalContent(prompt, references)
		messagesMetadata["attachments"] = chatGPTWebAttachmentMetadata(references)
	}
	payload := map[string]any{
		"action": "next",
		"messages": []any{
			map[string]any{
				"id":          uuid.NewString(),
				"author":      map[string]any{"role": "user"},
				"create_time": float64(time.Now().UnixNano()) / 1e9,
				"content":     messageContent,
				"metadata":    messagesMetadata,
			},
		},
		"parent_message_id":                    uuid.NewString(),
		"model":                                upstreamModel,
		"client_prepare_state":                 "sent",
		"timezone_offset_min":                  -480,
		"timezone":                             "Asia/Shanghai",
		"conversation_mode":                    map[string]any{"kind": "primary_assistant"},
		"enable_message_followups":             true,
		"system_hints":                         []string{chatGPTWebImageHint},
		"supports_buffering":                   true,
		"supported_encodings":                  []string{"v1"},
		"paragen_cot_summary_display_override": "allow",
		"force_parallel_switch":                "auto",
		"client_contextual_info": map[string]any{
			"is_dark_mode":      false,
			"time_since_loaded": 1200,
			"page_height":       1072,
			"page_width":        1724,
			"pixel_ratio":       1.2,
			"screen_height":     1440,
			"screen_width":      2560,
			"app_name":          "chatgpt.com",
		},
	}
	extra := map[string]string{
		"Accept":              "text/event-stream",
		"X-Oai-Turn-Trace-Id": uuid.NewString(),
	}
	if conduitToken != "" {
		extra["X-Conduit-Token"] = conduitToken
	}
	response, err := s.doJSON(ctx, http.MethodPost, path, payload, s.sentinelHeaders(path, sentinel, extra))
	if err != nil {
		return nil, fmt.Errorf("chatgpt web image generation: %w", err)
	}
	if response.StatusCode >= 400 {
		raw, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		_ = response.Body.Close()
		return nil, newChatGPTWebResponseError(response, "chatgpt web image generation", raw)
	}
	return response, nil
}

type chatGPTWebImageOutcome struct {
	ConversationID string
	Pointers       []string
}

// collectImagePointers 只接受工具或助手输出消息里的图片指针：
// 既排除用户输入附件，也排除上传占位。
func chatGPTWebCollectImagePointers(node any, conversationID *string, pointers *[]string) {
	switch value := node.(type) {
	case map[string]any:
		if id, ok := value["conversation_id"].(string); ok && strings.TrimSpace(id) != "" && *conversationID == "" {
			*conversationID = strings.TrimSpace(id)
		}
		candidate := false
		if author, ok := value["author"].(map[string]any); ok {
			if role, ok := author["role"].(string); ok && (role == "tool" || role == "assistant") {
				candidate = true
			}
		}
		if metadata, ok := value["metadata"].(map[string]any); ok {
			if taskType, ok := metadata["async_task_type"].(string); ok && taskType == "image_gen" {
				candidate = true
			}
		}
		if candidate {
			chatGPTWebCollectAssetPointers(value, pointers)
		}
		for key, child := range value {
			if key == "content" && candidate {
				continue
			}
			chatGPTWebCollectImagePointers(child, conversationID, pointers)
		}
	case []any:
		for _, child := range value {
			chatGPTWebCollectImagePointers(child, conversationID, pointers)
		}
	}
}

func chatGPTWebCollectAssetPointers(node any, pointers *[]string) {
	switch value := node.(type) {
	case map[string]any:
		if pointer, ok := value["asset_pointer"].(string); ok {
			if normalized := chatGPTWebNormalizePointer(pointer); normalized != "" {
				chatGPTWebAppendPointer(pointers, normalized)
			}
		}
		for _, child := range value {
			chatGPTWebCollectAssetPointers(child, pointers)
		}
	case []any:
		for _, child := range value {
			chatGPTWebCollectAssetPointers(child, pointers)
		}
	}
}

func chatGPTWebNormalizePointer(pointer string) string {
	trimmed := strings.TrimSpace(pointer)
	switch {
	case strings.HasPrefix(trimmed, "file-service://"), strings.HasPrefix(trimmed, "sediment://"):
		return trimmed
	case trimmed == "file_upload":
		return ""
	default:
		return ""
	}
}

func chatGPTWebAppendPointer(pointers *[]string, pointer string) {
	for _, existing := range *pointers {
		if existing == pointer {
			return
		}
	}
	*pointers = append(*pointers, pointer)
}

// consumeImageStream 消费 SSE：收集图片指针与 conversation_id。
func chatGPTWebConsumeImageStream(reader io.Reader, outcome *chatGPTWebImageOutcome) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		var decoded any
		if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
			continue
		}
		chatGPTWebCollectImagePointers(decoded, &outcome.ConversationID, &outcome.Pointers)
	}
	return scanner.Err()
}

// fetchConversationImages 是 SSE 未及时返回图片时的兜底：轮询会话详情直到出图或超时。
func (s *chatGPTWebSession) fetchConversationImages(
	ctx context.Context,
	conversationID string,
	outcome *chatGPTWebImageOutcome,
) error {
	if strings.TrimSpace(conversationID) == "" {
		return fmt.Errorf("chatgpt web image task is missing conversation id")
	}
	deadline := time.Now().Add(chatGPTWebPollTimeout)
	for {
		path := "/backend-api/conversation/" + conversationID
		response, err := s.doJSON(ctx, http.MethodGet, path, nil, map[string]string{"Accept": "application/json"})
		if err == nil {
			if body, bodyErr := readChatGPTWebBody(response); bodyErr == nil {
				var decoded any
				if json.Unmarshal(body, &decoded) == nil {
					chatGPTWebCollectImagePointers(decoded, &outcome.ConversationID, &outcome.Pointers)
					if len(outcome.Pointers) > 0 {
						return nil
					}
				}
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("chatgpt web image task timed out after %s", chatGPTWebPollTimeout)
		}
		timer := time.NewTimer(chatGPTWebPollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// deleteConversation removes a completed image-generation conversation from ChatGPT.
func (s *chatGPTWebSession) deleteConversation(ctx context.Context, conversationID string) error {
	if strings.TrimSpace(conversationID) == "" {
		return nil
	}
	path := "/backend-api/conversation/id/" + conversationID
	response, err := s.doJSON(ctx, http.MethodDelete, path, nil, map[string]string{
		"Accept":                "*/*",
		"Referer":               s.baseURL + "/c/" + conversationID,
		"X-OAI-Web-Frontend":    "core_web",
		"X-OpenAI-Target-Route": "/backend-api/conversation/id/{conversation_id}",
	})
	if err != nil {
		return err
	}
	_, err = readChatGPTWebBody(response)
	return err
}

func (s *chatGPTWebSession) cleanupImageConversation(ctx context.Context, conversationID string) {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := s.deleteConversation(cleanupCtx, conversationID); err != nil {
		logger.LegacyPrintf("service.openai_gateway", "[ChatGPTWebImage] conversation cleanup failed id=%s err=%v", conversationID, err)
	}
}

// scheduleImageConversationCleanup keeps best-effort sidebar cleanup off the
// response critical path. cleanupImageConversation detaches from request
// cancellation and applies its own timeout, so it remains safe after the
// caller returns or the downstream client disconnects.
func (s *chatGPTWebSession) scheduleImageConversationCleanup(ctx context.Context, conversationID string) {
	if strings.TrimSpace(conversationID) == "" {
		return
	}
	go s.cleanupImageConversation(ctx, conversationID)
}

// resolvePointerDownloadURL resolves a generated asset pointer into the signed
// URL issued by ChatGPT without downloading the image itself.
func (s *chatGPTWebSession) resolvePointerDownloadURL(
	ctx context.Context,
	conversationID string,
	pointer string,
) (string, error) {
	path := ""
	switch {
	case strings.HasPrefix(pointer, "file-service://"):
		path = "/backend-api/files/" + strings.TrimPrefix(pointer, "file-service://") + "/download"
	case strings.HasPrefix(pointer, "sediment://"):
		if strings.TrimSpace(conversationID) == "" {
			return "", fmt.Errorf("sediment pointer requires conversation id")
		}
		path = "/backend-api/conversation/" + conversationID + "/attachment/" +
			strings.TrimPrefix(pointer, "sediment://") + "/download"
	default:
		return "", fmt.Errorf("unsupported chatgpt web image pointer: %s", pointer)
	}

	var lastErr error
	for attempt := 0; attempt < chatGPTWebDownloadRetry; attempt++ {
		response, err := s.doJSON(ctx, http.MethodGet, path, nil, map[string]string{"Accept": "application/json"})
		if err == nil {
			body, bodyErr := readChatGPTWebBody(response)
			if bodyErr == nil {
				downloadURL := strings.TrimSpace(gjson.GetBytes(body, "download_url").String())
				if downloadURL == "" {
					downloadURL = strings.TrimSpace(gjson.GetBytes(body, "url").String())
				}
				if downloadURL != "" {
					return downloadURL, nil
				}
				lastErr = fmt.Errorf("chatgpt web image download url is empty")
			} else {
				lastErr = bodyErr
			}
		} else {
			lastErr = err
		}
		timer := time.NewTimer(750 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", ctx.Err()
		case <-timer.C:
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("chatgpt web image download failed")
	}
	return "", lastErr
}

// downloadPointer resolves an asset pointer and downloads its image bytes.
func (s *chatGPTWebSession) downloadPointer(
	ctx context.Context,
	conversationID string,
	pointer string,
) ([]byte, error) {
	downloadURL, err := s.resolvePointerDownloadURL(ctx, conversationID, pointer)
	if err != nil {
		return nil, err
	}
	return s.downloadBytes(ctx, downloadURL)
}

func (s *chatGPTWebSession) downloadBytes(ctx context.Context, target string) ([]byte, error) {
	headers := map[string]string{"Accept": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"}
	var (
		response *http.Response
		err      error
	)
	if isChatGPTWebFirstPartyURL(target) {
		headers["Sec-Fetch-Dest"] = "image"
		headers["Sec-Fetch-Mode"] = "no-cors"
		headers["Sec-Fetch-Site"] = "same-site"
		response, err = s.doChatGPTURLRequest(ctx, http.MethodGet, target, "", nil, headers)
	} else {
		response, err = s.doSignedAssetRequest(ctx, http.MethodGet, target, nil, headers)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 512))
		return nil, fmt.Errorf("chatgpt web image bytes HTTP %d: %s", response.StatusCode, truncateChatGPTWebText(string(body), 200))
	}
	return io.ReadAll(io.LimitReader(response.Body, 64<<20))
}

// imageQuota 读取网页侧 image_gen 剩余额度，用于账号调度与限流诊断。
func (s *chatGPTWebSession) imageQuota(ctx context.Context) (int, error) {
	path := "/backend-api/conversation/init"
	response, err := s.doJSON(ctx, http.MethodPost, path, map[string]any{
		"conversation_id":         nil,
		"gizmo_id":                nil,
		"requested_default_model": nil,
	}, nil)
	if err != nil {
		return 0, err
	}
	body, err := readChatGPTWebBody(response)
	if err != nil {
		return 0, err
	}
	for _, item := range gjson.GetBytes(body, "limits_progress").Array() {
		if item.Get("feature_name").String() == "image_gen" {
			return int(item.Get("remaining").Int()), nil
		}
	}
	return 0, nil
}

// chatGPTWebMaxImagesPerRequest 是单次请求允许的并发生图数上限。
// 网页端每条会话都是浏览器侧的真实回合，并发过高会触发账号滥用控制。
const chatGPTWebMaxImagesPerRequest = 4

// generateAndDownload 完成一次生图并下载其全部图片字节。
func (s *chatGPTWebSession) generateAndDownload(
	ctx context.Context,
	prompt string,
	requestModel string,
	upstreamModel string,
	references []*chatGPTWebReference,
) ([][]byte, error) {
	outcome, err := s.GenerateImage(ctx, prompt, requestModel, upstreamModel, references)
	if err != nil {
		return nil, err
	}
	defer s.scheduleImageConversationCleanup(ctx, outcome.ConversationID)
	images := make([][]byte, 0, len(outcome.Pointers))
	var lastErr error
	for _, pointer := range outcome.Pointers {
		raw, downloadErr := s.downloadPointer(ctx, outcome.ConversationID, pointer)
		if downloadErr != nil {
			lastErr = downloadErr
			continue
		}
		images = append(images, raw)
	}
	if len(images) == 0 {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("chatgpt web image generation returned no downloadable image")
	}
	return images, nil
}

func (s *chatGPTWebSession) generateAndResolveImageResults(
	ctx context.Context,
	prompt string,
	requestModel string,
	upstreamModel string,
	references []*chatGPTWebReference,
) ([]string, error) {
	outcome, err := s.GenerateImage(ctx, prompt, requestModel, upstreamModel, references)
	if err != nil {
		return nil, err
	}
	defer s.scheduleImageConversationCleanup(ctx, outcome.ConversationID)
	results := make([]string, 0, len(outcome.Pointers))
	var lastErr error
	for _, pointer := range outcome.Pointers {
		downloadURL, resolveErr := s.resolvePointerDownloadURL(ctx, outcome.ConversationID, pointer)
		if resolveErr != nil {
			lastErr = resolveErr
			continue
		}
		// Only cross-origin HTTPS asset URLs are independently usable by the
		// caller. ChatGPT first-party URLs require the account Authorization
		// headers, so preserve the old gateway-download behavior for them.
		parsedURL, parseErr := url.Parse(downloadURL)
		if parseErr == nil && strings.EqualFold(parsedURL.Scheme, "https") &&
			strings.TrimSpace(parsedURL.Hostname()) != "" && !isChatGPTWebFirstPartyURL(downloadURL) {
			results = append(results, downloadURL)
			continue
		}
		raw, downloadErr := s.downloadBytes(ctx, downloadURL)
		if downloadErr != nil {
			lastErr = downloadErr
			continue
		}
		mimeType := strings.ToLower(strings.TrimSpace(http.DetectContentType(raw)))
		if !strings.HasPrefix(mimeType, "image/") {
			lastErr = fmt.Errorf("chatgpt web image download returned non-image content type %s", mimeType)
			continue
		}
		results = append(results, "data:"+mimeType+";base64,"+base64.StdEncoding.EncodeToString(raw))
	}
	if len(results) == 0 {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("chatgpt web image generation returned no image result")
	}
	return results, nil
}

// GenerateImageResultBatch returns anonymous signed URLs when possible and
// data URLs when ChatGPT returns a first-party authenticated URL.
func (s *chatGPTWebSession) GenerateImageResultBatch(
	ctx context.Context,
	prompt string,
	requestModel string,
	upstreamModel string,
	references []*chatGPTWebReference,
	count int,
) ([]string, error) {
	if count <= 1 {
		return s.generateAndResolveImageResults(ctx, prompt, requestModel, upstreamModel, references)
	}
	type slot struct {
		results []string
		err     error
	}
	slots := make([]slot, count)
	var wait sync.WaitGroup
	for index := 0; index < count; index++ {
		wait.Add(1)
		go func(target int) {
			defer wait.Done()
			results, err := s.generateAndResolveImageResults(ctx, prompt, requestModel, upstreamModel, references)
			slots[target] = slot{results: results, err: err}
		}(index)
	}
	wait.Wait()

	merged := make([]string, 0, count)
	var firstErr error
	for _, item := range slots {
		if item.err != nil {
			if firstErr == nil {
				firstErr = item.err
			}
			continue
		}
		merged = append(merged, item.results...)
	}
	if len(merged) == 0 {
		if firstErr == nil {
			firstErr = fmt.Errorf("chatgpt web image generation returned no image result")
		}
		return nil, firstErr
	}
	return merged, nil
}

// GenerateImageBatch 生成 count 张图片。
//
// n 张 = n 次相互独立的网页会话并发执行（与参考实现的多线程语义一致），
// 每次会话各自取 sentinel、各自落一条 ChatGPT 会话；index 不参与 prompt 改写。
// 部分失败时返回已成功的图片：调用方至少能拿到可用结果，全部失败才返回错误。
func (s *chatGPTWebSession) GenerateImageBatch(
	ctx context.Context,
	prompt string,
	requestModel string,
	upstreamModel string,
	references []*chatGPTWebReference,
	count int,
) ([][]byte, error) {
	if count <= 1 {
		return s.generateAndDownload(ctx, prompt, requestModel, upstreamModel, references)
	}
	type slot struct {
		images [][]byte
		err    error
	}
	slots := make([]slot, count)
	var wait sync.WaitGroup
	for index := 0; index < count; index++ {
		wait.Add(1)
		go func(target int) {
			defer wait.Done()
			images, err := s.generateAndDownload(ctx, prompt, requestModel, upstreamModel, references)
			slots[target] = slot{images: images, err: err}
		}(index)
	}
	wait.Wait()

	merged := make([][]byte, 0, count)
	var firstErr error
	for _, item := range slots {
		if item.err != nil {
			if firstErr == nil {
				firstErr = item.err
			}
			continue
		}
		merged = append(merged, item.images...)
	}
	if len(merged) == 0 {
		if firstErr == nil {
			firstErr = fmt.Errorf("chatgpt web image generation returned no image")
		}
		return nil, firstErr
	}
	return merged, nil
}

// GenerateImage 生成一张或多张图片，返回去重后的指针与外层会话 id。
func (s *chatGPTWebSession) GenerateImage(
	ctx context.Context,
	prompt string,
	requestModel string,
	upstreamModel string,
	references []*chatGPTWebReference,
) (*chatGPTWebImageOutcome, error) {
	sentinel, err := s.fetchSentinel(ctx)
	if err != nil {
		return nil, err
	}
	model := chatGPTWebImageModelSettings(requestModel, upstreamModel)
	conduitToken, err := s.prepareImageConversation(ctx, prompt, sentinel, model, references)
	if err != nil {
		return nil, err
	}
	response, err := s.startImageGeneration(ctx, prompt, sentinel, conduitToken, model, references)
	if err != nil {
		return nil, err
	}
	outcome := &chatGPTWebImageOutcome{}
	streamErr := chatGPTWebConsumeImageStream(response.Body, outcome)
	_ = response.Body.Close()
	if streamErr != nil && len(outcome.Pointers) == 0 {
		s.scheduleImageConversationCleanup(ctx, outcome.ConversationID)
		return nil, streamErr
	}
	if len(outcome.Pointers) == 0 {
		if err := s.fetchConversationImages(ctx, outcome.ConversationID, outcome); err != nil {
			s.scheduleImageConversationCleanup(ctx, outcome.ConversationID)
			return nil, err
		}
	}
	return outcome, nil
}
