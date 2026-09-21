package config

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestV39OldConfigMigrationPreservesSettingsAndBackup(t *testing.T) {
	cfg := Default()
	cfg.ConfigVersion = 31
	cfg.Listen = "127.0.0.1:9888"
	cfg.RedactEvidence = true
	cfg.CallbackBaseURL = ""
	cfg.NormalPlugins = []string{"file_read"}
	cfg.PluginRules["file_read"] = PluginRuleConfig{ParameterNames: []string{"myField"}, Payloads: []PayloadRule{{Name: "custom", Payload: "/custom", Expected: "marker"}}}
	raw, _ := json.Marshal(cfg)
	var legacy map[string]any
	_ = json.Unmarshal(raw, &legacy)
	for _, key := range []string{"business_rules", "sms", "callback_wait_seconds", "callback_late_seconds"} {
		delete(legacy, key)
	}
	raw, _ = json.Marshal(legacy)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got := store.Get()
	if got.ConfigVersion != 35 || got.Listen != cfg.Listen || !got.RedactEvidence || got.CallbackBaseURL != "" || !reflect.DeepEqual(got.NormalPlugins, cfg.NormalPlugins) || !reflect.DeepEqual(got.PluginRules["file_read"], cfg.PluginRules["file_read"]) {
		t.Fatal("migration overwrote user configuration")
	}
	if got.SMS.Attempts != 30 || got.CallbackLateSeconds != 120 {
		t.Fatal("missing defaults")
	}
	backup, err := os.ReadFile(path + ".pre-v35.bak")
	if err != nil || !bytes.Equal(backup, raw) {
		t.Fatal("backup is not exact old file")
	}
	first, _ := os.ReadFile(path)
	if _, err = Open(path); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(path)
	if !bytes.Equal(first, second) {
		t.Fatal("second startup changed config")
	}
}
func TestV39BusinessRulesPersistenceValidation(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := store.Get()
	value := "OK"
	cfg.BusinessRules = []BusinessRule{{Name: "nested", JSONPath: "$.data.code", Equals: &value, Outcome: "success"}}
	cfg.CallbackWaitSeconds = 0
	cfg.CallbackLateSeconds = 0
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	again, err := Open(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(again.Get().BusinessRules, cfg.BusinessRules) || again.Get().CallbackLateSeconds != 0 {
		t.Fatal("settings not persisted")
	}
	cfg.BusinessRules[0].JSONPath = "$.data[*]"
	if cfg.Validate() == nil {
		t.Fatal("unsupported path accepted")
	}
}
