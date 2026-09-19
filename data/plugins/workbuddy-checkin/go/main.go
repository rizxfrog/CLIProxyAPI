package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);

static const cliproxy_host_api* stored_host;

static void store_host_api(const cliproxy_host_api* host) {
	stored_host = host;
}

static int call_host_api(const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	if (stored_host == NULL || stored_host->call == NULL) {
		return 1;
	}
	return stored_host->call(stored_host->host_ctx, method, request, request_len, response);
}

static void free_host_buffer(void* ptr, size_t len) {
	if (stored_host != NULL && stored_host->free_buffer != NULL && ptr != NULL) {
		stored_host->free_buffer(ptr, len);
	}
}
*/
import "C"

import (
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"gopkg.in/yaml.v3"
)

const (
	pluginName    = "workbuddy-checkin"
	pluginVersion = "1.0.0"

	// 资源菜单路径：Management UI 中的诊断/手动触发入口。
	resourcePath        = "/status"
	resourceContentType = "text/html; charset=utf-8"

	// 签到接口（参考 docs/scripts/workbuddy_checkin.py）。
	pathCheckinStatus = "/v2/billing/meter/checkin-activity-status"
	pathDailyCheckin  = "/v2/billing/meter/daily-checkin"

	// 默认时间窗：每日 00:10 ~ 03:10（共 180 分钟）。
	defaultWindowStartMin = 10
	defaultWindowEndMin   = 190 // 03:10 = 3*60+10

	// Legacy configuration field retained for compatibility. Daily scheduling now
	// assigns every account an independent time inside the configured window.
	defaultMaxJitterMin = 180
)

// ----------------------------------------------------------------- 信封
type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *envelopeError  `json:"error,omitempty"`
}

type envelopeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ----------------------------------------------------------------- 注册/配置
type registration struct {
	SchemaVersion uint32                   `json:"schema_version"`
	Metadata      pluginapi.Metadata       `json:"metadata"`
	Capabilities  registrationCapabilities `json:"capabilities"`
}

type registrationCapabilities struct {
	ManagementAPI bool `json:"management_api"`
}

type pluginConfig struct {
	Enabled        bool   `yaml:"enabled"`
	Priority       int    `yaml:"priority"`
	StartMin       int    `yaml:"window_start_min"`
	EndMin         int    `yaml:"window_end_min"`
	MaxJitterMin   int    `yaml:"max_jitter_min"`
	Endpoint       string `yaml:"endpoint"`
	Prefix         string `yaml:"prefix"`
	UserAgent      string `yaml:"user_agent"`
	RunImmediately bool   `yaml:"run_immediately"`
}

type managementRequest struct {
	Method         string
	Path           string
	Headers        map[string][]string
	Query          map[string][]string
	Body           []byte
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type managementResource struct {
	Path        string `json:"Path"`
	Menu        string `json:"Menu"`
	Description string `json:"Description"`
}

type managementRegistration struct {
	Resources []managementResource `json:"resources,omitempty"`
}

type managementResponse struct {
	StatusCode int                 `json:"StatusCode"`
	Headers    map[string][]string `json:"Headers"`
	Body       []byte              `json:"Body"`
}

// ----------------------------------------------------------------- 全局状态
var (
	cfgGuard  sync.RWMutex
	curConfig pluginConfig

	// 调度状态
	schedMu      sync.Mutex
	schedStarted bool
	nextRunAt    time.Time
	stopChan     chan struct{}
	wg           sync.WaitGroup
	runMu        sync.Mutex
)

func init() {
	curConfig = pluginConfig{
		Enabled:        false,
		Priority:       0,
		StartMin:       defaultWindowStartMin,
		EndMin:         defaultWindowEndMin,
		MaxJitterMin:   defaultMaxJitterMin,
		Endpoint:       "https://copilot.tencent.com",
		Prefix:         "codebuddy-cn",
		UserAgent:      "WorkBuddy/5.3.14",
		RunImmediately: false,
	}
}

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if plugin == nil {
		return 1
	}
	C.store_host_api(host)
	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeResponse(response, errorEnvelope("invalid_method", "method is required"))
		return 1
	}
	var requestBytes []byte
	if request != nil && requestLen > 0 {
		requestBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	raw, errHandle := handleMethod(C.GoString(method), requestBytes)
	if errHandle != nil {
		writeResponse(response, errorEnvelope("plugin_error", errHandle.Error()))
		return 1
	}
	writeResponse(response, raw)
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, len C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
	_ = len
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {
	stopScheduler()
}

func handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		if errConfigure := configure(request); errConfigure != nil {
			return nil, errConfigure
		}
		return okEnvelope(pluginRegistration())
	case pluginabi.MethodPluginQuiesce:
		stopScheduler()
		return okEnvelope(emptyResult{})
	case pluginabi.MethodManagementRegister:
		return okEnvelope(managementRegistration{
			Resources: []managementResource{{
				Path:        resourcePath,
				Menu:        "WorkBuddy 签到",
				Description: "查看每日签到调度状态，手动触发对所有 codebuddy-cn 凭证的签到。",
			}},
		})
	case pluginabi.MethodManagementHandle:
		return handleManagement(request)
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

func configure(raw []byte) error {
	var req struct {
		ConfigYAML []byte `json:"config_yaml"`
	}
	if len(raw) > 0 {
		if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
			return errUnmarshal
		}
	}
	c := curConfig
	if len(req.ConfigYAML) > 0 {
		decoded, errDecode := decodeConfig(req.ConfigYAML)
		if errDecode != nil {
			return errDecode
		}
		c = decoded
	}
	// 规范化
	if c.StartMin < 0 || c.StartMin > 1439 {
		c.StartMin = defaultWindowStartMin
	}
	if c.EndMin <= c.StartMin || c.EndMin > 1439 {
		c.EndMin = defaultWindowEndMin
	}
	if c.MaxJitterMin < 0 {
		c.MaxJitterMin = defaultMaxJitterMin
	}
	if strings.TrimSpace(c.Endpoint) == "" {
		c.Endpoint = "https://copilot.tencent.com"
	} else {
		c.Endpoint = strings.TrimRight(strings.TrimSpace(c.Endpoint), "/")
	}
	if strings.TrimSpace(c.Prefix) == "" {
		c.Prefix = "codebuddy-cn"
	}
	if strings.TrimSpace(c.UserAgent) == "" {
		c.UserAgent = "WorkBuddy/5.3.14"
	}
	cfgGuard.Lock()
	curConfig = c
	cfgGuard.Unlock()

	if c.Enabled {
		startScheduler()
	} else {
		stopScheduler()
	}
	return nil
}

func decodeConfig(raw []byte) (pluginConfig, error) {
	c := pluginConfig{
		StartMin:     defaultWindowStartMin,
		EndMin:       defaultWindowEndMin,
		MaxJitterMin: defaultMaxJitterMin,
		Endpoint:     "https://copilot.tencent.com",
		Prefix:       "codebuddy-cn",
		UserAgent:    "WorkBuddy/5.3.14",
	}
	if errUnmarshal := yaml.Unmarshal(raw, &c); errUnmarshal != nil {
		return pluginConfig{}, errUnmarshal
	}
	return c, nil
}

func currentConfig() pluginConfig {
	cfgGuard.RLock()
	defer cfgGuard.RUnlock()
	return curConfig
}

func pluginRegistration() registration {
	return registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             pluginName,
			Version:          pluginVersion,
			Author:           "router-for-me",
			GitHubRepository: "https://github.com/router-for-me/CLIProxyAPI",
			Logo:             "https://raw.githubusercontent.com/router-for-me/CLIProxyAPI/main/docs/logo.png",
			ConfigFields: []pluginapi.ConfigField{
				{
					Name:        "window_start_min",
					Type:        pluginapi.ConfigFieldTypeInteger,
					Description: "签到窗口起点（当天分钟数，默认 10 = 00:10）。",
				},
				{
					Name:        "window_end_min",
					Type:        pluginapi.ConfigFieldTypeInteger,
					Description: "签到窗口终点（当天分钟数，默认 190 = 03:10）。",
				},
				{
					Name:        "max_jitter_min",
					Type:        pluginapi.ConfigFieldTypeInteger,
					Description: "每个凭证的随机延时上限（分钟），默认 180，避免集中签到。",
				},
				{
					Name:        "endpoint",
					Type:        pluginapi.ConfigFieldTypeString,
					Description: "签到接口基地址，默认 https://copilot.tencent.com（可用凭证文件的 base_url 覆盖）。",
				},
				{
					Name:        "prefix",
					Type:        pluginapi.ConfigFieldTypeString,
					Description: "仅对文件名以此前缀开头的 .json 凭证执行签到，默认 codebuddy-cn。",
				},
				{
					Name:        "user_agent",
					Type:        pluginapi.ConfigFieldTypeString,
					Description: "请求 User-Agent，默认 WorkBuddy/5.3.14。",
				},
				{
					Name:        "run_immediately",
					Type:        pluginapi.ConfigFieldTypeBoolean,
					Description: "启用后，插件加载即立刻触发一次签到（绕过时间窗）。",
				},
			},
		},
		Capabilities: registrationCapabilities{
			ManagementAPI: true,
		},
	}
}

// ----------------------------------------------------------------- 调度
func startScheduler() {
	schedMu.Lock()
	defer schedMu.Unlock()
	if schedStarted {
		return
	}
	stopChan = make(chan struct{})
	schedStarted = true
	wg.Add(1)
	go schedulerLoop(stopChan)
}

func stopScheduler() {
	schedMu.Lock()
	if !schedStarted {
		schedMu.Unlock()
		return
	}
	close(stopChan)
	schedStarted = false
	schedMu.Unlock()
	wg.Wait()
}

type plannedCheckin struct {
	session session
	at      time.Time
}

// windowBounds returns today's configured window in the local server timezone.
func windowBounds(cfg pluginConfig, now time.Time) (time.Time, time.Time) {
	loc := now.Location()
	year, month, day := now.Date()
	base := time.Date(year, month, day, 0, 0, 0, 0, loc)
	return base.Add(time.Duration(cfg.StartMin) * time.Minute),
		base.Add(time.Duration(cfg.EndMin) * time.Minute)
}

// planCheckins assigns each account an independent random second in the
// remaining part of today's window. Accounts are planned before any request is
// made, so one slow account cannot delay all accounts behind it.
func planCheckins(cfg pluginConfig, now time.Time) ([]plannedCheckin, time.Time, error) {
	start, end := windowBounds(cfg, now)
	if !now.Before(end) {
		start = start.Add(24 * time.Hour)
		end = end.Add(24 * time.Hour)
		now = start
	}
	if now.Before(start) {
		now = start
	}

	sessions, err := loadSessions(cfg)
	if err != nil {
		return nil, start, err
	}
	available := int(end.Sub(now).Seconds())
	if available <= 0 {
		return nil, end, fmt.Errorf("签到窗口已结束")
	}

	planned := make([]plannedCheckin, 0, len(sessions))
	for _, s := range sessions {
		offset := randIntn(available)
		planned = append(planned, plannedCheckin{session: s, at: now.Add(time.Duration(offset) * time.Second)})
	}
	sort.Slice(planned, func(i, j int) bool { return planned[i].at.Before(planned[j].at) })
	return planned, start, nil
}

func waitUntil(stop <-chan struct{}, at time.Time) bool {
	d := time.Until(at)
	if d <= 0 {
		return true
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-stop:
		return false
	case <-timer.C:
		return true
	}
}

func schedulerLoop(stop chan struct{}) {
	defer wg.Done()
	for {
		cfg := currentConfig()
		now := time.Now()
		start, end := windowBounds(cfg, now)
		if !now.Before(end) {
			start = start.Add(24 * time.Hour)
		}
		if now.Before(start) {
			schedMu.Lock()
			nextRunAt = start
			schedMu.Unlock()
			if !waitUntil(stop, start) {
				return
			}
			continue
		}

		if !cfg.Enabled {
			if !waitUntil(stop, time.Now().Add(time.Minute)) {
				return
			}
			continue
		}

		planned, nextDay, errPlan := planCheckins(cfg, now)
		if errPlan != nil {
			hostLog("warn", "workbuddy-checkin: 生成每日签到计划失败: "+errPlan.Error())
			if !waitUntil(stop, nextDay.Add(24*time.Hour)) {
				return
			}
			continue
		}
		for _, item := range planned {
			schedMu.Lock()
			nextRunAt = item.at
			schedMu.Unlock()
			if !waitUntil(stop, item.at) {
				return
			}
			if currentConfig().Enabled {
				runCheckinOne(item.session, currentConfig())
			}
		}

		// Do not rebuild the plan repeatedly during the same window. The next
		// iteration starts at tomorrow's window and creates one fresh plan.
		nextStart, _ := windowBounds(cfg, now.Add(24*time.Hour))
		schedMu.Lock()
		nextRunAt = nextStart
		schedMu.Unlock()
		if !waitUntil(stop, nextStart) {
			return
		}
	}
}

func randIntn(n int) int {
	if n <= 0 {
		return 0
	}
	value, err := crand.Int(crand.Reader, big.NewInt(int64(n)))
	if err == nil {
		return int(value.Int64())
	}
	// Scheduling must remain functional even if the OS entropy source is
	// temporarily unavailable.
	return int(time.Now().UnixNano() % int64(n))
}

// ----------------------------------------------------------------- 签到执行
type session struct {
	token        string
	uid          string
	enterpriseID string
	domain       string
	endpoint     string
	name         string
}

// loadSessions 列出所有 codebuddy-cn 凭证，解码出 token/uid/endpoint。
func loadSessions(cfg pluginConfig) ([]session, error) {
	list, err := callHostAuthList()
	if err != nil {
		return nil, err
	}
	sessions := make([]session, 0)
	for _, f := range list {
		if !strings.HasPrefix(strings.ToLower(f.Name), strings.ToLower(cfg.Prefix)) {
			continue
		}
		if strings.TrimSpace(f.AuthIndex) == "" {
			continue
		}
		get, errGet := callHostAuthGet(f.AuthIndex)
		if errGet != nil {
			hostLog("warn", "workbuddy-checkin: 跳过 "+f.Name+": "+errGet.Error())
			continue
		}
		s, errParse := parseSession(get.JSON, cfg, f.Name)
		if errParse != nil {
			hostLog("warn", "workbuddy-checkin: 跳过 "+f.Name+": "+errParse.Error())
			continue
		}
		sessions = append(sessions, s)
	}
	if len(sessions) == 0 {
		return nil, fmt.Errorf("未发现匹配前缀 %q 的 codebuddy-cn 凭证", cfg.Prefix)
	}
	return sessions, nil
}

func parseSession(rawJSON json.RawMessage, cfg pluginConfig, name string) (session, error) {
	var data map[string]any
	if errUnmarshal := json.Unmarshal(rawJSON, &data); errUnmarshal != nil {
		return session{}, fmt.Errorf("凭证 JSON 无效: %w", errUnmarshal)
	}
	token, _ := data["access_token"].(string)
	if strings.TrimSpace(token) == "" {
		return session{}, fmt.Errorf("缺少 access_token")
	}
	uid := decodeJWTSub(token)
	if uid == "" {
		return session{}, fmt.Errorf("无法从 access_token 解出 uid")
	}
	endpoint := cfg.Endpoint
	if b, ok := data["base_url"].(string); ok && strings.TrimSpace(b) != "" {
		endpoint = strings.TrimRight(strings.TrimSpace(b), "/")
		if strings.HasSuffix(endpoint, "/v2") {
			endpoint = endpoint[:len(endpoint)-len("/v2")]
		}
	}
	s := session{
		token:        token,
		uid:          uid,
		enterpriseID: strOr(data, "enterprise_id", "enterpriseId"),
		domain:       strOr(data, "domain"),
		endpoint:     endpoint,
		name:         name,
	}
	return s, nil
}

func decodeJWTSub(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	payload := parts[1]
	// base64url padding
	raw, errDecode := base64.RawURLEncoding.DecodeString(payload)
	if errDecode != nil {
		return ""
	}
	var claims map[string]any
	if errUnmarshal := json.Unmarshal(raw, &claims); errUnmarshal != nil {
		return ""
	}
	if sub, ok := claims["sub"].(string); ok {
		return sub
	}
	return ""
}

func strOr(data map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := data[k].(string); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func buildHeaders(s session, ua string) map[string][]string {
	h := map[string][]string{
		"Accept":        {"application/json"},
		"Content-Type":  {"application/json"},
		"Authorization": {"Bearer " + s.token},
		"X-User-Id":     {s.uid},
		"User-Agent":    {ua},
	}
	if s.enterpriseID != "" {
		h["X-Enterprise-Id"] = []string{s.enterpriseID}
		h["X-Tenant-Id"] = []string{s.enterpriseID}
	}
	if s.domain != "" {
		h["X-Domain"] = []string{s.domain}
	}
	return h
}

// checkinStatus 查询签到状态，返回今日是否已签到。
func checkinStatus(s session, cfg pluginConfig) (bool, int, error) {
	url := s.endpoint + pathCheckinStatus
	resp, err := callHostHTTPDo("POST", url, buildHeaders(s, cfg.UserAgent), []byte("{}"))
	if err != nil {
		return false, 0, err
	}
	if resp.StatusCode != 200 {
		return false, resp.StatusCode, nil
	}
	var payload struct {
		Data *struct {
			TodayCheckedIn *bool `json:"today_checked_in"`
		} `json:"data"`
	}
	if errUnmarshal := json.Unmarshal(resp.Body, &payload); errUnmarshal != nil {
		return false, resp.StatusCode, fmt.Errorf("解析签到状态响应: %w", errUnmarshal)
	}
	if payload.Data == nil || payload.Data.TodayCheckedIn == nil {
		return false, resp.StatusCode, fmt.Errorf("签到状态响应缺少 data.today_checked_in")
	}
	return *payload.Data.TodayCheckedIn, resp.StatusCode, nil
}

// claimDailyCheckin 执行签到。
func claimDailyCheckin(s session, cfg pluginConfig) (bool, int, error) {
	url := s.endpoint + pathDailyCheckin
	resp, err := callHostHTTPDo("POST", url, buildHeaders(s, cfg.UserAgent), []byte("{}"))
	if err != nil {
		return false, 0, err
	}
	if resp.StatusCode != 200 {
		return false, resp.StatusCode, nil
	}
	var payload struct {
		Code *int `json:"code"`
	}
	if errUnmarshal := json.Unmarshal(resp.Body, &payload); errUnmarshal != nil {
		return false, resp.StatusCode, fmt.Errorf("解析签到响应: %w", errUnmarshal)
	}
	if payload.Code == nil {
		return false, resp.StatusCode, fmt.Errorf("签到响应缺少 code")
	}
	return *payload.Code == 0, resp.StatusCode, nil
}

// runCheckinOne performs one account's status check and claim. The scheduler
// decides the account's time before calling this function; this function never
// sleeps on behalf of other accounts.
func runCheckinOne(s session, cfg pluginConfig) {
	runMu.Lock()
	defer runMu.Unlock()

	already, statusCode, errStatus := checkinStatus(s, cfg)
	if errStatus != nil {
		hostLog("warn", "workbuddy-checkin: "+s.name+" 查询状态失败: "+errStatus.Error())
		return
	}
	if statusCode != 200 {
		hostLog("warn", fmt.Sprintf("workbuddy-checkin: %s 查询状态失败: HTTP %d", s.name, statusCode))
		return
	}
	if already {
		hostLog("info", "workbuddy-checkin: "+s.name+" 今日已签到")
		return
	}

	success, claimStatus, errClaim := claimDailyCheckin(s, cfg)
	if errClaim != nil {
		hostLog("warn", "workbuddy-checkin: "+s.name+" 签到失败: "+errClaim.Error())
		return
	}
	if success {
		hostLog("info", "workbuddy-checkin: "+s.name+" 签到成功")
		return
	}
	hostLog("warn", fmt.Sprintf("workbuddy-checkin: %s 签到未成功 HTTP %d", s.name, claimStatus))
}

// runCheckinAll is retained for the manual trigger. Manual execution is
// intentionally immediate; the daily scheduler uses runCheckinOne with its
// precomputed per-account schedule.
func runCheckinAll(cfg pluginConfig) {
	sessions, err := loadSessions(cfg)
	if err != nil {
		hostLog("warn", "workbuddy-checkin: "+err.Error())
		return
	}
	hostLog("info", fmt.Sprintf("workbuddy-checkin: 手动执行 %d 个凭证", len(sessions)))
	for _, s := range sessions {
		runCheckinOne(s, cfg)
	}
}

// ----------------------------------------------------------------- 宿主回调封装
func callHost(method string, payload any) (json.RawMessage, error) {
	rawPayload, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		return nil, fmt.Errorf("marshal host callback %s: %w", method, errMarshal)
	}
	cMethod := C.CString(method)
	defer C.free(unsafe.Pointer(cMethod))
	var response C.cliproxy_buffer
	var reqPtr *C.uint8_t
	if len(rawPayload) > 0 {
		cPayload := C.CBytes(rawPayload)
		if cPayload == nil {
			return nil, fmt.Errorf("allocate host callback payload %s", method)
		}
		defer C.free(cPayload)
		reqPtr = (*C.uint8_t)(cPayload)
	}
	code := C.call_host_api(cMethod, reqPtr, C.size_t(len(rawPayload)), &response)
	var rawResponse []byte
	if response.ptr != nil && response.len > 0 {
		rawResponse = C.GoBytes(response.ptr, C.int(response.len))
	}
	if response.ptr != nil {
		C.free_host_buffer(response.ptr, response.len)
	}
	if len(rawResponse) == 0 {
		return nil, fmt.Errorf("host callback %s returned no response", method)
	}
	var env envelope
	if errUnmarshal := json.Unmarshal(rawResponse, &env); errUnmarshal != nil {
		return nil, fmt.Errorf("decode host callback envelope %s: %w", method, errUnmarshal)
	}
	if !env.OK {
		if env.Error != nil {
			return nil, fmt.Errorf("%s: %s", env.Error.Code, env.Error.Message)
		}
		return nil, fmt.Errorf("host callback %s failed", method)
	}
	if code != 0 {
		return nil, fmt.Errorf("host callback %s returned code=%d", method, int(code))
	}
	return append(json.RawMessage(nil), env.Result...), nil
}

func callHostAuthList() ([]pluginapi.HostAuthFileEntry, error) {
	result, errCall := callHost(pluginabi.MethodHostAuthList, map[string]any{})
	if errCall != nil {
		return nil, errCall
	}
	var resp struct {
		Files []pluginapi.HostAuthFileEntry `json:"files"`
	}
	if errUnmarshal := json.Unmarshal(result, &resp); errUnmarshal != nil {
		return nil, fmt.Errorf("decode host.auth.list: %w", errUnmarshal)
	}
	return resp.Files, nil
}

func callHostAuthGet(authIndex string) (pluginapi.HostAuthGetResponse, error) {
	result, errCall := callHost(pluginabi.MethodHostAuthGet, pluginapi.HostAuthGetRequest{AuthIndex: authIndex})
	if errCall != nil {
		return pluginapi.HostAuthGetResponse{}, errCall
	}
	var resp pluginapi.HostAuthGetResponse
	if errUnmarshal := json.Unmarshal(result, &resp); errUnmarshal != nil {
		return pluginapi.HostAuthGetResponse{}, fmt.Errorf("decode host.auth.get: %w", errUnmarshal)
	}
	return resp, nil
}

func callHostHTTPDo(method, url string, headers map[string][]string, body []byte) (pluginapi.HTTPResponse, error) {
	payload := map[string]any{
		"method":  method,
		"url":     url,
		"headers": headers,
		"body":    body,
	}
	result, errCall := callHost(pluginabi.MethodHostHTTPDo, payload)
	if errCall != nil {
		return pluginapi.HTTPResponse{}, errCall
	}
	var resp pluginapi.HTTPResponse
	if errUnmarshal := json.Unmarshal(result, &resp); errUnmarshal != nil {
		return pluginapi.HTTPResponse{}, fmt.Errorf("decode host.http.do: %w", errUnmarshal)
	}
	return resp, nil
}

func hostLog(level, message string) {
	_, _ = callHost(pluginabi.MethodHostLog, map[string]any{
		"level":   level,
		"message": message,
	})
}

// ----------------------------------------------------------------- Management UI
func handleManagement(raw []byte) ([]byte, error) {
	var req managementRequest
	if len(raw) > 0 {
		if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
			return nil, fmt.Errorf("decode management request: %w", errUnmarshal)
		}
	}
	action := strings.ToLower(strings.TrimSpace(queryGet(req.Query, "action")))
	cfg := currentConfig()

	var result any
	var errRun error
	switch action {
	case "run":
		go runCheckinAll(cfg)
		result = map[string]any{"triggered": true, "message": "已后台触发签到任务"}
	case "config":
		result = cfg
	default:
		schedMu.Lock()
		next := nextRunAt
		schedMu.Unlock()
		result = map[string]any{
			"enabled":        cfg.Enabled,
			"window_start":   fmt.Sprintf("%02d:%02d", cfg.StartMin/60, cfg.StartMin%60),
			"window_end":     fmt.Sprintf("%02d:%02d", cfg.EndMin/60, cfg.EndMin%60),
			"max_jitter_min": cfg.MaxJitterMin,
			"endpoint":       cfg.Endpoint,
			"prefix":         cfg.Prefix,
			"next_run_at":    next.Format(time.RFC3339),
			"now":            time.Now().Format(time.RFC3339),
		}
	}

	if errRun != nil {
		page := renderPage(cfg, nil, errRun.Error())
		return okEnvelope(managementResponse{StatusCode: 200, Headers: map[string][]string{"content-type": {resourceContentType}}, Body: page})
	}
	page := renderPage(cfg, result, "")
	return okEnvelope(managementResponse{StatusCode: 200, Headers: map[string][]string{"content-type": {resourceContentType}}, Body: page})
}

func renderPage(cfg pluginConfig, result any, errText string) []byte {
	var out strings.Builder
	out.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><title>WorkBuddy 签到</title>")
	out.WriteString("<style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;padding:24px;line-height:1.5;color:#1f2933;background:#fff}main{max-width:760px;margin:0 auto}h1{margin:0 0 8px;font-size:24px}h2{margin:24px 0 10px;font-size:16px;border-bottom:1px solid #e5e7eb;padding-bottom:6px}p{margin:8px 0;color:#667085}dl{display:grid;grid-template-columns:160px 1fr;gap:8px 16px;margin:0}dt{color:#667085}dd{margin:0;word-break:break-word}code{background:#f3f4f6;padding:2px 5px;border-radius:4px}pre{margin:0;background:#f8fafc;border:1px solid #e5e7eb;padding:12px;border-radius:6px;overflow:auto;white-space:pre-wrap}a{color:#2563eb;text-decoration:none}a:hover{text-decoration:underline}.actions{margin:18px 0}.err{color:#b42318}</style>")
	out.WriteString("</head><body><main>")
	out.WriteString("<h1>WorkBuddy 每日签到</h1>")
	out.WriteString("<p>每天在配置的时间窗口内，为匹配的账号随机安排签到时间。</p>")
	out.WriteString("<div class=\"actions\"><a href=\"?action=run\">立即签到</a>　<a href=\"?action=config\">查看配置</a></div>")
	out.WriteString("<h2>运行状态</h2><dl>")
	writeDT(&out, "状态", map[bool]string{true: "已启用", false: "已停用"}[cfg.Enabled])
	writeDT(&out, "签到窗口", fmt.Sprintf("%02d:%02d ~ %02d:%02d", cfg.StartMin/60, cfg.StartMin%60, cfg.EndMin/60, cfg.EndMin%60))
	writeDT(&out, "凭证前缀", cfg.Prefix)
	schedMu.Lock()
	next := nextRunAt
	schedMu.Unlock()
	writeDT(&out, "下次计划", next.Format(time.RFC3339))
	writeDT(&out, "当前时间", time.Now().Format(time.RFC3339))
	out.WriteString("</dl>")
	if errText != "" {
		out.WriteString("<h2 class=\"err\">Error</h2><pre class=\"err\">")
		out.WriteString(htmlEscape(errText))
		out.WriteString("</pre>")
	}
	if result != nil {
		out.WriteString("<h2>执行结果</h2><pre>")
		out.WriteString(htmlEscape(prettyJSON(result)))
		out.WriteString("</pre>")
	}
	out.WriteString("</main></body></html>")
	return []byte(out.String())
}

func queryGet(q map[string][]string, key string) string {
	if q == nil {
		return ""
	}
	vals := q[strings.ToLower(key)]
	if len(vals) == 0 {
		vals = q[key]
	}
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

func writeDT(out *strings.Builder, k, v string) {
	out.WriteString("<dt>")
	out.WriteString(htmlEscape(k))
	out.WriteString("</dt><dd><code>")
	out.WriteString(htmlEscape(v))
	out.WriteString("</code></dd>")
}

func prettyJSON(v any) string {
	raw, errMarshal := json.MarshalIndent(v, "", "  ")
	if errMarshal != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(raw)
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;")
	return r.Replace(s)
}

// ----------------------------------------------------------------- 工具
type emptyResult struct{}

func okEnvelope(v any) ([]byte, error) {
	raw, errMarshal := json.Marshal(v)
	if errMarshal != nil {
		return nil, errMarshal
	}
	return json.Marshal(envelope{OK: true, Result: raw})
}

func errorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Message: message}})
	return raw
}

func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}
