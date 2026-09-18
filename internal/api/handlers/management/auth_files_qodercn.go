package management

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/watcher/synthesizer"
)

// qoderCNKeyWithAuthIndex is a Qoder CN credential plus the live auth index of
// its synthesized runtime auth entry, so the Web UI can correlate config rows
// with the running auth pool.
type qoderCNKeyWithAuthIndex struct {
	config.QoderCNKey
	AuthIndex string `json:"auth-index,omitempty"`
}

// Compile-time guard: the management routes in server_management.go reference
// these methods by name, so removing or renaming one must fail the build here
// rather than at route registration. Method expressions bind the receiver as
// the first parameter.
var (
	_ func(*Handler, *gin.Context) = (*Handler).GetQoderCNKeys
	_ func(*Handler, *gin.Context) = (*Handler).PutQoderCNKeys
	_ func(*Handler, *gin.Context) = (*Handler).PatchQoderCNKey
	_ func(*Handler, *gin.Context) = (*Handler).DeleteQoderCNKey
)

// normalizeQoderCNKey trims and normalizes one Qoder CN credential.
func normalizeQoderCNKey(entry *config.QoderCNKey) {
	if entry == nil {
		return
	}
	entry.APIKey = strings.TrimSpace(entry.APIKey)
	entry.RefreshToken = strings.TrimSpace(entry.RefreshToken)
	entry.MachineID = strings.TrimSpace(entry.MachineID)
	entry.Prefix = strings.TrimSpace(entry.Prefix)
	entry.BaseURL = strings.TrimSpace(entry.BaseURL)
	entry.ProxyURL = strings.TrimSpace(entry.ProxyURL)
	entry.Headers = config.NormalizeHeaders(entry.Headers)
	entry.ExcludedModels = config.NormalizeExcludedModels(entry.ExcludedModels)
	if len(entry.Models) == 0 {
		return
	}
	out := entry.Models[:0]
	seen := make(map[string]struct{}, len(entry.Models))
	for i := range entry.Models {
		model := entry.Models[i]
		model.Name = strings.TrimSpace(model.Name)
		model.Alias = strings.TrimSpace(model.Alias)
		if model.Name == "" && model.Alias == "" {
			continue
		}
		key := model.Name + "|" + model.Alias
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, model)
	}
	entry.Models = out
}

// qoderCNKeysWithAuthIndex decorates each credential with its live auth index.
func (h *Handler) qoderCNKeysWithAuthIndex() []qoderCNKeyWithAuthIndex {
	if h == nil {
		return nil
	}
	liveIndexByID := h.liveAuthIndexByID()

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cfg == nil {
		return nil
	}

	idGen := synthesizer.NewStableIDGenerator()
	entries := h.cfg.QoderCNKey
	out := make([]qoderCNKeyWithAuthIndex, len(entries))
	for i := range entries {
		entry := entries[i]
		authIndex := ""
		if key := strings.TrimSpace(entry.APIKey); key != "" {
			id, _ := idGen.Next("qoder-cn:apikey", key, entry.BaseURL, entry.MachineID)
			authIndex = liveIndexByID[id]
		}
		out[i] = qoderCNKeyWithAuthIndex{QoderCNKey: entry, AuthIndex: authIndex}
	}
	return out
}

// qoder-cn-api-key: []QoderCNKey
func (h *Handler) GetQoderCNKeys(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"qoder-cn-api-key": h.qoderCNKeysWithAuthIndex()})
}

// PutQoderCNKeys replaces the full Qoder CN credential list.
func (h *Handler) PutQoderCNKeys(c *gin.Context) {
	data, errRead := c.GetRawData()
	if errRead != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}
	var arr []config.QoderCNKey
	if errUnmarshal := json.Unmarshal(data, &arr); errUnmarshal != nil {
		var obj struct {
			Items []config.QoderCNKey `json:"items"`
		}
		if errObject := json.Unmarshal(data, &obj); errObject != nil || len(obj.Items) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
			return
		}
		arr = obj.Items
	}

	filtered := make([]config.QoderCNKey, 0, len(arr))
	for i := range arr {
		entry := arr[i]
		normalizeQoderCNKey(&entry)
		if entry.APIKey == "" {
			continue
		}
		if rejectInvalidCredentialWeight(c, fmt.Sprintf("qoder-cn-api-key[%d].weight", i), entry.Weight) {
			return
		}
		filtered = append(filtered, entry)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	h.cfg.QoderCNKey = filtered
	h.cfg.SanitizeQoderCNKeys()
	h.persistLocked(c)
}

// qoderCNKeyPatch is the PATCH body for one Qoder CN credential.
type qoderCNKeyPatch struct {
	APIKey         *string                `json:"api-key"`
	RefreshToken   *string                `json:"refresh-token"`
	MachineID      *string                `json:"machine-id"`
	Priority       *int                   `json:"priority"`
	Weight         json.RawMessage        `json:"weight"`
	Prefix         *string                `json:"prefix"`
	BaseURL        *string                `json:"base-url"`
	ProxyURL       *string                `json:"proxy-url"`
	Models         *[]config.QoderCNModel `json:"models"`
	Headers        *map[string]string     `json:"headers"`
	ExcludedModels *[]string              `json:"excluded-models"`
	DisableCooling json.RawMessage        `json:"disable-cooling"`
}

// PatchQoderCNKey updates one Qoder CN credential selected by index or api-key.
func (h *Handler) PatchQoderCNKey(c *gin.Context) {
	var body struct {
		Index *int             `json:"index"`
		Match *string          `json:"match"`
		Value *qoderCNKeyPatch `json:"value"`
	}
	if errBind := c.ShouldBindJSON(&body); errBind != nil || body.Value == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	entries := h.cfg.QoderCNKey
	targetIndex := -1
	if body.Index != nil && *body.Index >= 0 && *body.Index < len(entries) {
		targetIndex = *body.Index
	}
	if targetIndex == -1 && body.Match != nil {
		match := strings.TrimSpace(*body.Match)
		for i := range entries {
			if entries[i].APIKey == match {
				targetIndex = i
				break
			}
		}
	}
	if targetIndex == -1 {
		c.JSON(http.StatusNotFound, gin.H{"error": "item not found"})
		return
	}

	entry := entries[targetIndex]
	if body.Value.APIKey != nil {
		entry.APIKey = strings.TrimSpace(*body.Value.APIKey)
	}
	if body.Value.RefreshToken != nil {
		entry.RefreshToken = strings.TrimSpace(*body.Value.RefreshToken)
	}
	if body.Value.MachineID != nil {
		entry.MachineID = strings.TrimSpace(*body.Value.MachineID)
	}
	if body.Value.Priority != nil {
		entry.Priority = *body.Value.Priority
	}
	if len(body.Value.Weight) > 0 {
		weight, errWeight := parseCredentialWeightPatch(body.Value.Weight)
		if errWeight != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": errWeight.Error()})
			return
		}
		entry.Weight = weight
	}
	if body.Value.Prefix != nil {
		entry.Prefix = strings.TrimSpace(*body.Value.Prefix)
	}
	if body.Value.BaseURL != nil {
		entry.BaseURL = strings.TrimSpace(*body.Value.BaseURL)
	}
	if body.Value.ProxyURL != nil {
		entry.ProxyURL = strings.TrimSpace(*body.Value.ProxyURL)
	}
	if body.Value.Models != nil {
		entry.Models = append([]config.QoderCNModel(nil), (*body.Value.Models)...)
	}
	if body.Value.Headers != nil {
		entry.Headers = config.NormalizeHeaders(*body.Value.Headers)
	}
	if body.Value.ExcludedModels != nil {
		entry.ExcludedModels = config.NormalizeExcludedModels(*body.Value.ExcludedModels)
	}
	if !applyDisableCoolingPatch(c, body.Value.DisableCooling, &entry.DisableCooling) {
		return
	}

	normalizeQoderCNKey(&entry)
	entries[targetIndex] = entry
	h.cfg.QoderCNKey = entries
	h.cfg.SanitizeQoderCNKeys()
	h.persistLocked(c)
}

// DeleteQoderCNKey removes one Qoder CN credential.
func (h *Handler) DeleteQoderCNKey(c *gin.Context) {
	h.mu.Lock()
	defer h.mu.Unlock()
	entries := h.cfg.QoderCNKey

	if val := strings.TrimSpace(c.Query("api-key")); val != "" {
		out := make([]config.QoderCNKey, 0, len(entries))
		removed := 0
		for _, entry := range entries {
			if strings.TrimSpace(entry.APIKey) == val {
				removed++
				continue
			}
			out = append(out, entry)
		}
		if removed == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "item not found"})
			return
		}
		h.cfg.QoderCNKey = out
		h.persistLocked(c)
		return
	}

	rawIndex := strings.TrimSpace(c.Query("index"))
	if rawIndex == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "api-key or index is required"})
		return
	}
	index := -1
	if _, errScan := fmt.Sscanf(rawIndex, "%d", &index); errScan != nil || index < 0 || index >= len(entries) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "index out of range"})
		return
	}
	h.cfg.QoderCNKey = append(append([]config.QoderCNKey(nil), entries[:index]...), entries[index+1:]...)
	h.persistLocked(c)
}
