package middleware

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestManagementRiskScoreDistinguishesBrowserAndCurl(t *testing.T) {
	browser := httptest.NewRequest("GET", "/v0/management/config", nil)
	browser.Header.Set("User-Agent", "Mozilla/5.0 Chrome/124.0.0.0")
	browser.Header.Set("Accept-Language", "en-US,en;q=0.9")
	browser.Header.Set("Sec-Fetch-Site", "same-origin")
	browser.Header.Set("Sec-Fetch-Mode", "cors")
	browser.Header.Set("Sec-Fetch-Dest", "empty")
	browser.Header.Set("Referer", "https://example.test/management.html")

	curl := httptest.NewRequest("GET", "/v0/management/config", nil)
	curl.Header.Set("User-Agent", "curl/8.0")

	if browserScore := managementRiskScore(browser, normalizeUserAgentFragments(nil)); browserScore >= defaultManagementBlockScore {
		t.Fatalf("browser score = %d, want below block score", browserScore)
	}
	if curlScore := managementRiskScore(curl, normalizeUserAgentFragments(nil)); curlScore < defaultManagementBlockScore {
		t.Fatalf("curl score = %d, want at least block score", curlScore)
	}
}

func TestManagementAntiBotMiddlewareOnlyBlocksRemoteSuspiciousRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(ManagementAntiBotMiddleware(config.ManagementAntiBotConfig{Enabled: true}, nil))
	router.GET("/v0/management/config", func(c *gin.Context) { c.Status(200) })

	local := httptest.NewRecorder()
	localReq := httptest.NewRequest("GET", "/v0/management/config", nil)
	localReq.RemoteAddr = "127.0.0.1:1234"
	router.ServeHTTP(local, localReq)
	if local.Code != 200 {
		t.Fatalf("local status = %d, want 200", local.Code)
	}

	remote := httptest.NewRecorder()
	remoteReq := httptest.NewRequest("GET", "/v0/management/config", nil)
	remoteReq.RemoteAddr = "203.0.113.10:1234"
	remoteReq.Header.Set("User-Agent", "curl/8.0")
	router.ServeHTTP(remote, remoteReq)
	if remote.Code != 403 {
		t.Fatalf("remote suspicious status = %d, want 403", remote.Code)
	}
}

func TestManagementAntiBotLimiter(t *testing.T) {
	limiter := NewManagementAntiBotLimiter()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	limiter.now = func() time.Time { return now }

	if allowed, _ := limiter.acquire("ip", 1, 1, now); !allowed {
		t.Fatal("first request was rejected")
	}
	if allowed, _ := limiter.acquire("ip", 1, 1, now); allowed {
		t.Fatal("second request was accepted above the rate limit")
	}
	limiter.release("ip")
	now = now.Add(time.Minute)
	if allowed, _ := limiter.acquire("ip", 1, 1, now); !allowed {
		t.Fatal("request was rejected after the rate window elapsed")
	}
}
