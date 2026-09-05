package managementasset

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestSafeStaticAssetPath(t *testing.T) {
	dir := t.TempDir()

	valid := []string{
		"@index.html",
		"@assets/css/app.css",
		"@foo/bar/baz.js",
	}
	for _, p := range valid {
		got, err := SafeStaticAssetPath(dir, p)
		if err != nil {
			t.Fatalf("SafeStaticAssetPath(%q) error = %v", p, err)
		}
		// The "@" prefix is part of the on-disk filename and is preserved.
		want := filepath.Join(dir, filepath.FromSlash(p))
		if got != want {
			t.Fatalf("SafeStaticAssetPath(%q) = %q, want %q", p, got, want)
		}
	}

	invalid := []string{
		"",
		"index.html",        // no @ prefix
		"assets/index.html", // no @ prefix
		"../@index.html",    // traversal before @
		"@a/../../secret",   // traversal resolves away the @ segment
		"@a\\..\\secret",    // backslash traversal
	}
	for _, p := range invalid {
		if _, err := SafeStaticAssetPath(dir, p); err == nil {
			t.Fatalf("SafeStaticAssetPath(%q) expected error, got nil", p)
		}
	}

	// Empty dir must error.
	if _, err := SafeStaticAssetPath("", "@index.html"); err == nil {
		t.Fatalf("SafeStaticAssetPath with empty dir expected error, got nil")
	}
}

func TestSafeStaticAssetPathRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = outside

	// Attempt to escape the static dir via a symlink-free relative traversal.
	for _, p := range []string{"../@index.html", "@x/../../secret.txt"} {
		got, err := SafeStaticAssetPath(dir, p)
		if err == nil {
			t.Fatalf("SafeStaticAssetPath(%q) = %q, want error", p, got)
		}
	}
}

func TestFetchLatestAssetSetsGitHubAuthorization(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "asset-token")
	t.Setenv("GITSTORE_GIT_TOKEN", "")
	t.Setenv("GITSTORE_GIT_URL", "")

	var authorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		authorization = req.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"assets":[{"name":"@management.html","browser_download_url":"https://example.com/@management.html","digest":"sha256:abc123"}]}`))
	}))
	defer server.Close()

	asset, remoteHash, err := fetchLatestAsset(t.Context(), server.Client(), server.URL)
	if err != nil {
		t.Fatalf("fetchLatestAsset() error = %v", err)
	}
	if authorization != "Bearer asset-token" {
		t.Fatalf("Authorization = %q, want %q", authorization, "Bearer asset-token")
	}
	if asset == nil || asset.Name != managementAssetName {
		t.Fatalf("asset = %#v, want %q", asset, managementAssetName)
	}
	if remoteHash != "abc123" {
		t.Fatalf("remoteHash = %q, want %q", remoteHash, "abc123")
	}
}

func TestFetchLatestAssetOmitsAuthorizationWithoutToken(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("github_token", "")
	t.Setenv("GITSTORE_GIT_TOKEN", "")
	t.Setenv("GITSTORE_GIT_URL", "")

	var authorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		authorization = req.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"assets":[{"name":"@management.html","browser_download_url":"https://example.com/@management.html","digest":"sha256:abc123"}]}`))
	}))
	defer server.Close()

	asset, remoteHash, err := fetchLatestAsset(t.Context(), server.Client(), server.URL)
	if err != nil {
		t.Fatalf("fetchLatestAsset() error = %v", err)
	}
	if authorization != "" {
		t.Fatalf("Authorization = %q, want empty", authorization)
	}
	if asset == nil || asset.Name != managementAssetName {
		t.Fatalf("asset = %#v, want %q", asset, managementAssetName)
	}
	if remoteHash != "abc123" {
		t.Fatalf("remoteHash = %q, want %q", remoteHash, "abc123")
	}
}

func TestAutoUpdateSkipReason(t *testing.T) {
	tests := []struct {
		name       string
		cfg        *config.Config
		wantReason string
		wantSkip   bool
	}{
		{
			name:       "nil config",
			cfg:        nil,
			wantReason: "config not yet available",
			wantSkip:   true,
		},
		{
			name: "cluster mode",
			cfg: &config.Config{
				Home: config.HomeConfig{Enabled: true},
			},
			wantReason: "cluster mode enabled",
			wantSkip:   true,
		},
		{
			name: "control panel disabled",
			cfg: &config.Config{
				RemoteManagement: config.RemoteManagement{DisableControlPanel: true},
			},
			wantReason: "control panel disabled",
			wantSkip:   true,
		},
		{
			name: "auto update disabled",
			cfg: &config.Config{
				RemoteManagement: config.RemoteManagement{DisableAutoUpdatePanel: true},
			},
			wantReason: "disable-auto-update-panel is enabled",
			wantSkip:   true,
		},
		{
			name:       "enabled",
			cfg:        &config.Config{},
			wantReason: "",
			wantSkip:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotReason, gotSkip := autoUpdateSkipReason(tt.cfg)
			if gotReason != tt.wantReason || gotSkip != tt.wantSkip {
				t.Fatalf("autoUpdateSkipReason() = (%q, %t), want (%q, %t)", gotReason, gotSkip, tt.wantReason, tt.wantSkip)
			}
		})
	}
}
