package service

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/sha3"
)

// ChatGPT Web 网页链路的 sentinel proof-of-work token 生成。
//
// 网页链路（chatgpt.com /backend-api/sentinel/chat-requirements）要求客户端提交
// proof token：对 seed + base64(指纹 JSON) 做 SHA3-512，命中 difficulty 前缀即算解出。
// 该计算完全本地可做，不需要浏览器；这正是账号 access_token 能直接驱动官网生图的原因。

const (
	chatGPTWebDefaultPowScript  = "https://chatgpt.com/backend-api/sentinel/sdk.js"
	chatGPTWebPowFallbackPrefix = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"
	chatGPTWebPowMaxAttempts    = 500000
)

// 指纹候选值尽量贴近真实浏览器，避免与账号既有设备画像冲突。
var chatGPTWebNavigatorKeys = []string{
	"registerProtocolHandler\u2212function registerProtocolHandler() { [native code] }",
	"storage\u2212[object StorageManager]",
	"locks\u2212[object LockManager]",
	"appCodeName\u2212Mozilla",
	"permissions\u2212[object Permissions]",
	"share\u2212function share() { [native code] }",
	"webdriver\u2212false",
	"managed\u2212[object NavigatorManagedData]",
	"canShare\u2212function canShare() { [native code] }",
	"vendor\u2212Google Inc.",
	"mediaDevices\u2212[object MediaDevices]",
	"vibrate\u2212function vibrate() { [native code] }",
	"storageBuckets\u2212[object StorageBucketManager]",
	"mediaCapabilities\u2212[object MediaCapabilities]",
	"cookieEnabled\u2212true",
	"virtualKeyboard\u2212[object VirtualKeyboard]",
	"product\u2212Gecko",
	"presentation\u2212[object Presentation]",
	"onLine\u2212true",
	"mimeTypes\u2212[object MimeTypeArray]",
	"credentials\u2212[object CredentialsContainer]",
	"serviceWorker\u2212[object ServiceWorkerContainer]",
	"keyboard\u2212[object Keyboard]",
	"gpu\u2212[object GPU]",
	"doNotTrack",
	"serial\u2212[object Serial]",
	"pdfViewerEnabled\u2212true",
	"language\u2212zh-CN",
	"geolocation\u2212[object Geolocation]",
	"userAgentData\u2212[object NavigatorUAData]",
	"getUserMedia\u2212function getUserMedia() { [native code] }",
	"sendBeacon\u2212function sendBeacon() { [native code] }",
	"hardwareConcurrency\u221232",
	"windowControlsOverlay\u2212[object WindowControlsOverlay]",
}

var chatGPTWebWindowKeys = []string{
	"0", "window", "self", "document", "name", "location", "customElements", "history",
	"navigation", "innerWidth", "innerHeight", "scrollX", "scrollY", "visualViewport",
	"screenX", "screenY", "outerWidth", "outerHeight", "devicePixelRatio", "screen",
	"chrome", "navigator", "onresize", "performance", "crypto", "indexedDB",
	"sessionStorage", "localStorage", "scheduler", "alert", "atob", "btoa", "fetch",
	"matchMedia", "postMessage", "queueMicrotask", "requestAnimationFrame", "setInterval",
	"setTimeout", "caches", "__NEXT_DATA__", "__BUILD_MANIFEST", "__NEXT_PRELOADREADY",
}

var chatGPTWebDocumentKeys = []string{
	"__reactContainer$fzelfjyxej8", "_reactListening5dehydibo78", "location",
}

var chatGPTWebScreenResolutions = [][2]int{{1920, 1080}, {1440, 900}, {2560, 1440}, {3840, 2160}}

var chatGPTWebPowCores = []int{8, 16, 24, 32}

var (
	chatGPTWebScriptSrcPattern    = regexp.MustCompile(`<script[^>]+src="([^"]+)"`)
	chatGPTWebDataBuildSrcPattern = regexp.MustCompile(`c/[^/]*/_`)
	chatGPTWebDataBuildAttrPatt   = regexp.MustCompile(`<html[^>]*data-build="([^"]*)"`)
)

// chatGPTWebProcessStart 提供 config 中的 performance.now 基准（进程内单调时钟）。
var chatGPTWebProcessStart = time.Now()

func chatGPTWebPerfNowMillis() float64 {
	return float64(time.Since(chatGPTWebProcessStart).Microseconds()) / 1000.0
}

func chatGPTWebLegacyParseTime(now time.Time) string {
	eastern := now.In(time.FixedZone("EST", -5*3600))
	return eastern.Format("Mon Jan 02 2006 15:04:05") + " GMT-0500 (Eastern Standard Time)"
}

func chatGPTWebCompactJSON(value any) string {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return ""
	}
	return strings.TrimRight(buf.String(), "\n")
}

func chatGPTWebPickString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	index, err := rand.Int(rand.Reader, big.NewInt(int64(len(values))))
	if err != nil {
		return values[0]
	}
	return values[index.Int64()]
}

func chatGPTWebRandomFloat() float64 {
	index, err := rand.Int(rand.Reader, big.NewInt(1<<53))
	if err != nil {
		return 0.5
	}
	return float64(index.Int64()) / float64(int64(1)<<53)
}

func chatGPTWebRandomInt(limit int) int {
	if limit <= 1 {
		return 0
	}
	index, err := rand.Int(rand.Reader, big.NewInt(int64(limit)))
	if err != nil {
		return 0
	}
	return int(index.Int64())
}

// chatGPTWebPowConfig 构造与浏览器一致的指纹数组，顺序不可调整。
func chatGPTWebPowConfig(userAgent string, scriptSources []string, dataBuild string) []any {
	resolution := chatGPTWebScreenResolutions[chatGPTWebRandomInt(len(chatGPTWebScreenResolutions))]
	scriptSource := chatGPTWebDefaultPowScript
	if len(scriptSources) > 0 {
		scriptSource = chatGPTWebPickString(scriptSources)
	}
	perfNow := chatGPTWebPerfNowMillis()
	return []any{
		resolution[0] + resolution[1],
		chatGPTWebLegacyParseTime(time.Now()),
		int64(4294705152),
		1,
		userAgent,
		scriptSource,
		dataBuild,
		"en-US",
		"en-US,es-US,en,es",
		chatGPTWebRandomFloat(),
		chatGPTWebPickString(chatGPTWebNavigatorKeys),
		chatGPTWebPickString(chatGPTWebDocumentKeys),
		chatGPTWebPickString(chatGPTWebWindowKeys),
		perfNow,
		uuid.NewString(),
		"",
		chatGPTWebPowCores[chatGPTWebRandomInt(len(chatGPTWebPowCores))],
		float64(time.Now().UnixMilli()) - perfNow,
		0, 0, 0, 0, 0, 0,
		0,
	}
}

// parseChatGPTWebPowResources 从首页 HTML 里解析 sentinel sdk 脚本地址与构建号。
// 两者会进入指纹 JSON，缺失时退化为默认脚本地址，不影响 PoW 求解。
func parseChatGPTWebPowResources(html string) ([]string, string) {
	matches := chatGPTWebScriptSrcPattern.FindAllStringSubmatch(html, -1)
	sources := make([]string, 0, len(matches))
	dataBuild := ""
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		src := strings.TrimSpace(match[1])
		if src == "" {
			continue
		}
		sources = append(sources, src)
		if dataBuild == "" {
			dataBuild = chatGPTWebDataBuildSrcPattern.FindString(src)
		}
	}
	if dataBuild == "" {
		if match := chatGPTWebDataBuildAttrPatt.FindStringSubmatch(html); len(match) >= 2 {
			dataBuild = match[1]
		}
	}
	if len(sources) == 0 {
		sources = []string{chatGPTWebDefaultPowScript}
	}
	return sources, dataBuild
}

// chatGPTWebBuildRequirementsToken 生成 chat-requirements/prepare 的 `p` 字段。
func chatGPTWebBuildRequirementsToken(userAgent string, scriptSources []string, dataBuild string) string {
	config := chatGPTWebPowConfig(userAgent, scriptSources, dataBuild)
	payload := chatGPTWebCompactJSON(config)
	return "gAAAAAC" + base64.StdEncoding.EncodeToString([]byte(payload))
}

// chatGPTWebBuildProofToken 解出 proofofwork 挑战并返回 OpenAI-Sentinel-Proof-Token。
func chatGPTWebBuildProofToken(seed, difficulty, userAgent string, scriptSources []string, dataBuild string) (string, error) {
	config := chatGPTWebPowConfig(userAgent, scriptSources, dataBuild)
	if strings.TrimSpace(difficulty) == "" {
		difficulty = "0"
	}
	answer, solved := chatGPTWebPowGenerate(seed, difficulty, config, chatGPTWebPowMaxAttempts)
	if !solved {
		return "", fmt.Errorf("chatgpt web proof token unsolved: difficulty=%s", difficulty)
	}
	return "gAAAAAB" + answer, nil
}

// chatGPTWebPowGenerate 求解 PoW：命中即返回 base64(指纹 JSON)，未命中返回 false。
// 组装顺序固定为 config[0:3] + i + config[4:9] + i>>1 + config[10:]，与网页端脚本一致。
func chatGPTWebPowGenerate(seed, difficulty string, config []any, limit int) (string, bool) {
	if len(config) < 11 {
		return "", false
	}
	target, err := hex.DecodeString(strings.TrimSpace(difficulty))
	if err != nil || len(target) == 0 {
		return "", false
	}
	head := strings.TrimSuffix(chatGPTWebCompactJSON(config[:3]), "]") + ","
	middle := chatGPTWebCompactJSON(config[4:9])
	middle = "," + strings.TrimSuffix(strings.TrimPrefix(middle, "["), "]") + ","
	tail := "," + strings.TrimPrefix(chatGPTWebCompactJSON(config[10:]), "[")
	seedBytes := []byte(seed)

	hasher := sha3.New512()
	for i := 0; i < limit; i++ {
		payload := head + strconv.Itoa(i) + middle + strconv.Itoa(i>>1) + tail
		encoded := base64.StdEncoding.EncodeToString([]byte(payload))
		hasher.Reset()
		_, _ = hasher.Write(seedBytes)
		_, _ = hasher.Write([]byte(encoded))
		digest := hasher.Sum(nil)
		if bytes.Compare(digest[:len(target)], target) <= 0 {
			return encoded, true
		}
	}
	return "", false
}
