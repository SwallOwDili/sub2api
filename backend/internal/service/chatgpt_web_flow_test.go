//go:build unit

package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"image"
	"image/color"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

type webImageFixtureUpstream struct {
	HTTPUpstream
	image         []byte
	paths         []string
	assetRequests []*http.Request
}

func (f *webImageFixtureUpstream) Do(req *http.Request, _ string, _ int64, _ int) (*http.Response, error) {
	if !HTTPUpstreamPublicHostsOnly(req.Context()) {
		return nil, errors.New("signed asset request did not enforce public-host validation")
	}
	if req.Header.Get("Authorization") != "" || req.Header.Get("OAI-Device-Id") != "" || req.Header.Get("OAI-Session-Id") != "" {
		return nil, errors.New("signed asset request leaked ChatGPT credentials")
	}
	f.assetRequests = append(f.assetRequests, req.Clone(req.Context()))
	switch {
	case req.URL.Host == "reference.example" && req.URL.Path == "/reference.png" && req.Method == http.MethodGet:
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(f.image))}, nil
	case req.URL.Host == "fixture.example" && req.URL.Path == "/upload" && req.Method == http.MethodPut:
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(nil))}, nil
	case req.URL.Host == "fixture.example" && req.URL.Path == "/image.png" && req.Method == http.MethodGet:
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(f.image))}, nil
	default:
		return nil, errors.New("unexpected signed asset request: " + req.URL.String())
	}
}

func (f *webImageFixtureUpstream) DoWithTLS(req *http.Request, _ string, _ int64, _ int, profile *tlsfingerprint.Profile) (*http.Response, error) {
	if profile == nil || profile.Preset != tlsfingerprint.PresetChrome {
		return nil, errors.New("web image request must use Chrome TLS preset")
	}
	f.paths = append(f.paths, req.URL.Path)
	if !HTTPUpstreamRedirectsDisabled(req.Context()) {
		return nil, errors.New("authenticated web image request did not disable redirects")
	}
	if req.URL.Host == "chatgpt.com" && req.URL.Path != "/" && req.Header.Get("Authorization") != "Bearer fixture-access" {
		return nil, errors.New("web image request did not use account access_token")
	}
	var body string
	switch req.URL.Path {
	case "/":
		body = `<html><script src="/backend-api/sentinel/sdk.js"></script></html>`
	case "/backend-api/sentinel/chat-requirements/prepare":
		body = `{"prepare_token":"fixture-prepare","proofofwork":{"required":false}}`
	case "/backend-api/sentinel/chat-requirements/finalize":
		body = `{"token":"fixture-sentinel"}`
	case "/backend-api/files":
		body = `{"file_id":"fixture-input","upload_url":"https://fixture.example/upload"}`
	case "/backend-api/files/fixture-input/uploaded":
		body = `{}`
	case "/backend-api/f/conversation/prepare":
		body = `{"conduit_token":"fixture-conduit"}`
	case "/backend-api/f/conversation":
		body = "data: {\"v\":{\"conversation_id\":\"fixture-conversation\",\"message\":{\"author\":{\"role\":\"tool\"},\"metadata\":{\"async_task_type\":\"image_gen\"},\"content\":{\"parts\":[{\"asset_pointer\":\"file-service://fixture-image\"}]}}}}\n\n"
	case "/backend-api/files/fixture-image/download":
		body = `{"download_url":"https://fixture.example/image.png"}`
	default:
		return nil, errors.New("unexpected upstream path: " + req.URL.Path)
	}
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewBufferString(body))}, nil
}

func TestWebImageAccountCreateScheduleForwardFixture(t *testing.T) {
	picture := image.NewRGBA(image.Rect(0, 0, 1, 1))
	picture.Set(0, 0, color.RGBA{R: 255, A: 255})
	var encoded bytes.Buffer
	require.NoError(t, png.Encode(&encoded, picture))

	account, err := buildAccountForCreate(&CreateAccountInput{
		Name: "web-image-fixture", Platform: PlatformOpenAI, Type: AccountTypeWebImage,
		Credentials: map[string]any{"access_token": "fixture-access", "refresh_token": "fixture-refresh"},
		Concurrency: 1,
	}, map[string]any{})
	require.NoError(t, err)
	account.ID = 9201
	transport := &webImageFixtureUpstream{image: encoded.Bytes()}
	svc := &OpenAIGatewayService{
		accountRepo: schedulerTestOpenAIAccountRepo{accounts: []Account{*account}},
		cache:       &schedulerTestGatewayCache{}, cfg: &config.Config{},
		concurrencyService: NewConcurrencyService(schedulerTestConcurrencyCache{}), httpUpstream: transport,
	}
	selection, _, err := svc.SelectAccountWithSchedulerForImages(context.Background(), nil, "", "gpt-image-2.5-sunburst", nil, OpenAIImagesCapabilityNative)
	require.NoError(t, err)
	require.NotNil(t, selection)
	require.Equal(t, account.ID, selection.Account.ID)
	if selection.ReleaseFunc != nil {
		defer selection.ReleaseFunc()
	}

	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/images/generations", nil)
	parsed := &OpenAIImagesRequest{
		Endpoint: "/v1/images/generations", Model: "gpt-image-2.5-sunburst", Prompt: "a red apple",
		N: 1, Size: "1024x1024", SizeTier: "1024", ResponseFormat: "b64_json",
		InputImageURLs: []string{"https://reference.example/reference.png"},
	}
	forwarded, err := svc.ForwardImages(c.Request.Context(), c, selection.Account, nil, parsed, "")
	require.NoError(t, err)
	require.Equal(t, 1, forwarded.ImageCount)
	require.Equal(t, http.StatusOK, recorder.Code)
	raw, err := base64.StdEncoding.DecodeString(gjson.GetBytes(recorder.Body.Bytes(), "data.0.b64_json").String())
	require.NoError(t, err)
	require.Equal(t, encoded.Bytes(), raw)
	require.Contains(t, transport.paths, "/backend-api/f/conversation")
	require.NotContains(t, transport.paths, "/backend-api/codex/responses")
	require.Len(t, transport.assetRequests, 3)
	require.Equal(t, http.MethodGet, transport.assetRequests[0].Method)
	require.Equal(t, "reference.example", transport.assetRequests[0].URL.Host)
	require.Equal(t, http.MethodPut, transport.assetRequests[1].Method)
	require.Equal(t, "fixture.example", transport.assetRequests[1].URL.Host)
	require.Equal(t, http.MethodGet, transport.assetRequests[2].Method)
}
