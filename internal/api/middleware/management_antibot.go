package middleware

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

const (
	defaultManagementRequestsPerMinute = 120
	defaultManagementMaxConcurrent     = 20
	defaultManagementBlockScore        = 70
	managementWindow                   = time.Minute
)

type managementClientState struct {
	windowStart time.Time
	requests    int
	inFlight    int
}

// ManagementAntiBotLimiter provides process-local protection for remote
// Management API requests. It intentionally does not inspect model/API-key
// request routes and does not attempt to identify clients with TLS fingerprints.
type ManagementAntiBotLimiter struct {
	mu      sync.Mutex
	clients map[string]*managementClientState
	now     func() time.Time
}

// NewManagementAntiBotLimiter creates a limiter ready for use.
func NewManagementAntiBotLimiter() *ManagementAntiBotLimiter {
	return &ManagementAntiBotLimiter{clients: make(map[string]*managementClientState)}
}

// ManagementAntiBotMiddleware applies browser-signal scoring and per-IP limits
// to remote management requests. Localhost clients are deliberately bypassed so
// a local operator cannot lock themselves out with curl during recovery.
func ManagementAntiBotMiddleware(cfg config.ManagementAntiBotConfig, limiter *ManagementAntiBotLimiter) gin.HandlerFunc {
	if limiter == nil {
		limiter = NewManagementAntiBotLimiter()
	}
	requestsPerMinute := cfg.MaxRequestsPerMinute
	if requestsPerMinute <= 0 {
		requestsPerMinute = defaultManagementRequestsPerMinute
	}
	maxConcurrent := cfg.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = defaultManagementMaxConcurrent
	}
	blockScore := cfg.BlockScore
	if blockScore <= 0 {
		blockScore = defaultManagementBlockScore
	}
	userAgents := normalizeUserAgentFragments(cfg.SuspiciousUserAgents)

	return func(c *gin.Context) {
		if !cfg.Enabled || c == nil || c.Request == nil {
			c.Next()
			return
		}
		if c.Request.Method == http.MethodOptions || isLocalManagementClient(c.ClientIP()) {
			c.Next()
			return
		}

		clientIP := c.ClientIP()
		if clientIP == "" {
			clientIP = "unknown"
		}
		allowed, retryAfter := limiter.acquire(clientIP, requestsPerMinute, maxConcurrent, limiterTime(limiter))
		if !allowed {
			if retryAfter > 0 {
				c.Header("Retry-After", retryAfter.String())
			}
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "management_rate_limited",
			})
			return
		}
		defer limiter.release(clientIP)

		if managementRiskScore(c.Request, userAgents) >= blockScore {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "management_browser_verification_required",
			})
			return
		}
		c.Next()
	}
}

func (l *ManagementAntiBotLimiter) acquire(ip string, maxPerMinute, maxConcurrent int, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.clients == nil {
		l.clients = make(map[string]*managementClientState)
	}
	state := l.clients[ip]
	if state == nil || now.Sub(state.windowStart) >= managementWindow || now.Before(state.windowStart) {
		state = &managementClientState{windowStart: now}
		l.clients[ip] = state
	}
	if state.requests >= maxPerMinute {
		retryAfter := state.windowStart.Add(managementWindow).Sub(now)
		if retryAfter < 0 {
			retryAfter = 0
		}
		return false, retryAfter
	}
	if state.inFlight >= maxConcurrent {
		return false, time.Second
	}
	state.requests++
	state.inFlight++
	return true, 0
}

func (l *ManagementAntiBotLimiter) release(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if state := l.clients[ip]; state != nil && state.inFlight > 0 {
		state.inFlight--
	}
}

func limiterTime(l *ManagementAntiBotLimiter) time.Time {
	if l != nil && l.now != nil {
		return l.now()
	}
	return time.Now()
}

func isLocalManagementClient(ip string) bool {
	return ip == "127.0.0.1" || ip == "::1" || ip == "localhost"
}

func normalizeUserAgentFragments(values []string) []string {
	if len(values) == 0 {
		values = []string{"curl", "wget", "python-requests", "python", "httpclient", "scrapy", "go-http-client"}
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.ToLower(strings.TrimSpace(value)); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func managementRiskScore(req *http.Request, suspiciousUserAgents []string) int {
	if req == nil {
		return defaultManagementBlockScore
	}
	score := 0
	ua := strings.ToLower(strings.TrimSpace(req.Header.Get("User-Agent")))
	if ua == "" {
		score += 40
	} else {
		for _, fragment := range suspiciousUserAgents {
			if strings.Contains(ua, fragment) {
				score += 70
				break
			}
		}
	}

	if strings.TrimSpace(req.Header.Get("Accept-Language")) == "" {
		score += 10
	}
	fetchSite := strings.ToLower(strings.TrimSpace(req.Header.Get("Sec-Fetch-Site")))
	fetchMode := strings.ToLower(strings.TrimSpace(req.Header.Get("Sec-Fetch-Mode")))
	fetchDest := strings.ToLower(strings.TrimSpace(req.Header.Get("Sec-Fetch-Dest")))
	if fetchSite == "" && fetchMode == "" && fetchDest == "" {
		score += 15
	} else {
		if fetchSite != "" && fetchSite != "same-origin" && fetchSite != "same-site" && fetchSite != "none" {
			score += 20
		}
		if fetchMode == "navigate" && fetchDest != "document" {
			score += 10
		}
	}
	if strings.TrimSpace(req.Header.Get("Origin")) == "" && strings.TrimSpace(req.Header.Get("Referer")) == "" {
		score += 10
	}
	return score
}
