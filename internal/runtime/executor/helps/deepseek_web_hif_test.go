package helps

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestDeepSeekWebHifClientFetchesAndInjectsHeaders(t *testing.T) {
	var leimCalls, dliqCalls atomic.Int32
	leimSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		leimCalls.Add(1)
		w.Header().Set("x-hif-ttl", "600")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"msg":"","data":{"biz_code":0,"biz_msg":"","biz_data":{"value":"leim-token-value"}}}`))
	}))
	defer leimSrv.Close()
	dliqSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		dliqCalls.Add(1)
		w.Header().Set("x-hif-ttl", "600")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"msg":"","data":{"biz_code":0,"biz_msg":"","biz_data":{"value":"dliq-token-value"}}}`))
	}))
	defer dliqSrv.Close()

	client := NewDeepSeekWebHifClient(&config.Config{})
	client.leimURL = leimSrv.URL
	client.dliqURL = dliqSrv.URL

	ctx := context.Background()
	if got := client.LeimHeader(ctx, nil); got != "leim-token-value" {
		t.Fatalf("LeimHeader() = %q, want %q", got, "leim-token-value")
	}
	if got := client.DliqHeader(ctx, nil); got != "dliq-token-value" {
		t.Fatalf("DliqHeader() = %q, want %q", got, "dliq-token-value")
	}
	if leimCalls.Load() != 1 || dliqCalls.Load() != 1 {
		t.Fatalf("expected 1 fetch each, got leim=%d dliq=%d", leimCalls.Load(), dliqCalls.Load())
	}
}

func TestDeepSeekWebHifClientCachesWithinTTL(t *testing.T) {
	var leimCalls atomic.Int32
	leimSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		leimCalls.Add(1)
		w.Header().Set("x-hif-ttl", "600")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"msg":"","data":{"biz_code":0,"biz_msg":"","biz_data":{"value":"cached-leim"}}}`))
	}))
	defer leimSrv.Close()
	dliqSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("x-hif-ttl", "600")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"msg":"","data":{"biz_code":0,"biz_msg":"","biz_data":{"value":"cached-dliq"}}}`))
	}))
	defer dliqSrv.Close()

	client := NewDeepSeekWebHifClient(&config.Config{})
	client.leimURL = leimSrv.URL
	client.dliqURL = dliqSrv.URL

	ctx := context.Background()
	if got := client.LeimHeader(ctx, nil); got != "cached-leim" {
		t.Fatalf("first LeimHeader() = %q", got)
	}
	if got := client.LeimHeader(ctx, nil); got != "cached-leim" {
		t.Fatalf("second LeimHeader() = %q", got)
	}
	if leimCalls.Load() != 1 {
		t.Fatalf("expected 1 leim fetch (cached), got %d", leimCalls.Load())
	}
}

func TestDeepSeekWebHifClientDegradesOnError(t *testing.T) {
	leimSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer leimSrv.Close()

	client := NewDeepSeekWebHifClient(&config.Config{})
	client.leimURL = leimSrv.URL
	client.dliqURL = leimSrv.URL

	ctx := context.Background()
	if got := client.LeimHeader(ctx, nil); got != "" {
		t.Fatalf("LeimHeader() on failure = %q, want empty (degrade)", got)
	}
}

func TestDeepSeekWebHifClientRefreshesAfterExpiry(t *testing.T) {
	var leimCalls atomic.Int32
	var value atomic.Value
	value.Store("first-token")
	leimSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		leimCalls.Add(1)
		w.Header().Set("x-hif-ttl", "1") // 1 second TTL
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"msg":"","data":{"biz_code":0,"biz_msg":"","biz_data":{"value":"` + value.Load().(string) + `"}}}`))
	}))
	defer leimSrv.Close()
	dliqSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("x-hif-ttl", "1")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"msg":"","data":{"biz_code":0,"biz_msg":"","biz_data":{"value":"dliq"}}}`))
	}))
	defer dliqSrv.Close()

	client := NewDeepSeekWebHifClient(&config.Config{})
	client.leimURL = leimSrv.URL
	client.dliqURL = dliqSrv.URL

	ctx := context.Background()
	if got := client.LeimHeader(ctx, nil); got != "first-token" {
		t.Fatalf("first LeimHeader() = %q", got)
	}
	value.Store("second-token")
	time.Sleep(1100 * time.Millisecond)
	if got := client.LeimHeader(ctx, nil); got != "second-token" {
		t.Fatalf("LeimHeader() after expiry = %q, want %q", got, "second-token")
	}
	if leimCalls.Load() != 2 {
		t.Fatalf("expected 2 leim fetches, got %d", leimCalls.Load())
	}
}
