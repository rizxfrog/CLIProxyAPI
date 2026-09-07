package trae

import (
	"net/url"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestConfigIdentityReusesUnclaimedEntry(t *testing.T) {
	cfg := &config.Config{
		TraeKey: []config.TraeKey{
			{APIKey: "existing-token", MachineID: "bound-machine", DeviceID: "bound-device"},
			{MachineID: "aha-machine", DeviceID: "4241644404954854"},
		},
	}
	machineID, deviceID := ConfigIdentity(cfg)
	if machineID != "aha-machine" {
		t.Fatalf("machine id = %q, want aha-machine", machineID)
	}
	if deviceID != "4241644404954854" {
		t.Fatalf("device id = %q, want 4241644404954854", deviceID)
	}
}

func TestConfigIdentitySkipsAuthenticatedEntries(t *testing.T) {
	cfg := &config.Config{
		TraeKey: []config.TraeKey{
			{APIKey: "existing-token", MachineID: "bound-machine", DeviceID: "bound-device"},
		},
	}
	machineID, deviceID := ConfigIdentity(cfg)
	if machineID != "" || deviceID != "" {
		t.Fatalf("identity = (%q,%q), want empty when only authenticated entries exist", machineID, deviceID)
	}
}

func TestBuildLoginURLWithIdentityUsesProvidedValues(t *testing.T) {
	client := NewClient(nil)
	login, errBuild := client.BuildLoginURLWithIdentity("machine-1", "4241644404954854")
	if errBuild != nil {
		t.Fatalf("BuildLoginURLWithIdentity error: %v", errBuild)
	}
	if login.MachineID != "machine-1" || login.DeviceID != "4241644404954854" {
		t.Fatalf("identity = (%q,%q), want (machine-1,4241644404954854)", login.MachineID, login.DeviceID)
	}
	parsed, errParse := url.Parse(login.URL)
	if errParse != nil {
		t.Fatalf("parse login url: %v", errParse)
	}
	query := parsed.Query()
	if query.Get("device_id") != "4241644404954854" {
		t.Fatalf("device_id = %q, want 4241644404954854", query.Get("device_id"))
	}
	if query.Get("machine_id") != "machine-1" {
		t.Fatalf("machine_id = %q, want machine-1", query.Get("machine_id"))
	}
}

func TestBuildLoginURLGeneratesHexIdentity(t *testing.T) {
	client := NewClient(nil)
	login, errBuild := client.BuildLoginURL()
	if errBuild != nil {
		t.Fatalf("BuildLoginURL error: %v", errBuild)
	}
	if len(login.MachineID) != 32 || len(login.DeviceID) != 32 {
		t.Fatalf("generated identity should be hex32, got machine=%q device=%q", login.MachineID, login.DeviceID)
	}
	if strings.TrimSpace(login.State) == "" {
		t.Fatal("state should not be empty")
	}
}
