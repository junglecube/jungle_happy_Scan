package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestSQL381UpgradeRetainsCustomRulesAndNormalCost(t *testing.T) {
	cfg := Default()
	cfg.ConfigVersion = 31
	cfg.NormalPlugins = []string{"sqli", "sqli_extended", "sensitive_data"}
	rule := cfg.PluginRules["sqli_timing"]
	rule.Payloads = []PayloadRule{
		{Name: "custom control", Kind: "time_control", Group: "custom", Payload: "{{value}} AND SLEEP(0)=0", Expected: "4"},
		{Name: "custom delay", Kind: "time_delay", Group: "custom", Payload: "{{value}} AND SLEEP(4)=0", Expected: "4"},
	}
	cfg.PluginRules["sqli_timing"] = rule
	path := filepath.Join(t.TempDir(), "config.json")
	data, _ := json.Marshal(cfg)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	upgraded := store.Get()
	if !slices.Equal(upgraded.NormalPlugins, []string{"sqli", "sensitive_data"}) {
		t.Fatalf("Normal silently enabled timing: %v", upgraded.NormalPlugins)
	}
	groups := map[string]int{}
	for _, p := range upgraded.PluginRules["sqli_timing"].Payloads {
		groups[p.Group]++
		if p.Group == "custom" && p.Expected != "4" {
			t.Fatal("custom delay overwritten")
		}
	}
	for _, group := range []string{"custom", "mysql-sleep-and-select-exact-replace", "postgres-reported-tail-exact-replace", "postgres-parenthesis-tail-exact-replace", "postgres-stacked-string"} {
		if groups[group] != 2 {
			t.Fatalf("missing paired migration %s: %v", group, groups)
		}
	}
	if err := store.Save(upgraded); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err != nil {
		t.Fatalf("upgrade is not idempotent: %v", err)
	}
}
