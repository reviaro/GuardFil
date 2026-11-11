package budget

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseModels(t *testing.T) {
	ok := "models:\n  - {provider: openai, model: gpt-6-sol, input_usd_per_million_tokens: 3, output_usd_per_million_tokens: 12}\n" +
		"  - {provider: anthropic, model: claude-sonnet-5-5, input_usd_per_million_tokens: 2, output_usd_per_million_tokens: 10}\n"
	if e, err := ParseModels([]byte(ok)); err != nil || len(e) != 2 {
		t.Fatalf("valid list: %v %v", e, err)
	}
	if e, err := ParseModels(nil); err != nil || len(e) != 0 {
		t.Fatalf("empty file: %v %v", e, err)
	}
	for name, doc := range map[string]string{
		"unknown provider":  "models: [{provider: azure, model: x, input_usd_per_million_tokens: 1, output_usd_per_million_tokens: 1}]",
		"bad name":          "models: [{provider: openai, model: 'GPT 6', input_usd_per_million_tokens: 1, output_usd_per_million_tokens: 1}]",
		"zero price":        "models: [{provider: openai, model: m, input_usd_per_million_tokens: 0, output_usd_per_million_tokens: 1}]",
		"fraction":          "models: [{provider: openai, model: m, input_usd_per_million_tokens: 0.5, output_usd_per_million_tokens: 1}]",
		"too expensive":     "models: [{provider: openai, model: m, input_usd_per_million_tokens: 1, output_usd_per_million_tokens: 10001}]",
		"duplicate":         "models: [{provider: openai, model: m, input_usd_per_million_tokens: 1, output_usd_per_million_tokens: 1}, {provider: openai, model: m, input_usd_per_million_tokens: 1, output_usd_per_million_tokens: 1}]",
		"built-in repriced": "models: [{provider: openai, model: gpt-6-luna, input_usd_per_million_tokens: 2, output_usd_per_million_tokens: 2}]",
		"built-in new tier": "models: [{provider: openai, model: claude-sonnet-5-5, input_usd_per_million_tokens: 2, output_usd_per_million_tokens: 10}]",
		"built-in wrong provider gemini for openai":     "models: [{provider: gemini, model: gpt-6-luna, input_usd_per_million_tokens: 1, output_usd_per_million_tokens: 1}]",
		"built-in wrong provider openai for gemini":     "models: [{provider: openai, model: gemini-3.6-flash, input_usd_per_million_tokens: 2, output_usd_per_million_tokens: 8}]",
		"built-in wrong provider openai for gemini-3.8": "models: [{provider: openai, model: gemini-3.8-flash, input_usd_per_million_tokens: 2, output_usd_per_million_tokens: 8}]",
		"built-in repriced gemini-3.8":                  "models: [{provider: gemini, model: gemini-3.8-flash, input_usd_per_million_tokens: 3, output_usd_per_million_tokens: 8}]",
		"unknown key":                                   "models: [{provider: openai, model: m, input_usd_per_million_tokens: 1, output_usd_per_million_tokens: 1, cached: 1}]",
		"unknown top":                                   "extra: 1",
	} {
		if _, err := ParseModels([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLoadModels(t *testing.T) {
	saveRates, saveModels := ModelRates, ProviderModels
	t.Cleanup(func() { ModelRates, ProviderModels = saveRates, saveModels })
	ModelRates = map[string]ModelRate{}
	for k, v := range saveRates {
		ModelRates[k] = v
	}
	ProviderModels = map[string]map[string]bool{}
	for p, m := range saveModels {
		ProviderModels[p] = map[string]bool{}
		for k := range m {
			ProviderModels[p][k] = true
		}
	}
	dir := t.TempDir()
	if err := LoadModels(filepath.Join(dir, "missing.yaml")); err != nil {
		t.Fatalf("missing file: %v", err)
	}
	if AllowedModel("openai", "gpt-6-sol") || !AllowedModel("openai", PinnedModel) {
		t.Fatal("built-ins only")
	}
	p := filepath.Join(dir, "models.yaml")
	doc := "models: [{provider: openai, model: gpt-6-sol, input_usd_per_million_tokens: 3, output_usd_per_million_tokens: 12}]\n"
	if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := LoadModels(p); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("group-readable file accepted: %v", err)
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if err := LoadModels(link); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := LoadModels(p); err != nil {
		t.Fatal(err)
	}
	if !AllowedModel("openai", "gpt-6-sol") || AllowedModel("anthropic", "gpt-6-sol") {
		t.Fatal("listed model not allowed for its provider only")
	}
	if c, err := ModelCostMicros("gpt-6-sol", "default", 1000, 100); err != nil || c != 1000*3+100*12 {
		t.Fatalf("cost %d %v", c, err)
	}
}

func TestGemini38Builtin(t *testing.T) {
	// gemini-3.8-flash is built-in and allowed for gemini
	if !AllowedModel("gemini", "gemini-3.8-flash") {
		t.Fatal("gemini-3.8-flash must be allowed for gemini")
	}
	if AllowedModel("openai", "gemini-3.8-flash") {
		t.Fatal("gemini-3.8-flash must not be allowed for openai")
	}

	// Listing gemini-3.8-flash under gemini at its built-in price is valid
	validGemini38 := "models: [{provider: gemini, model: gemini-3.8-flash, input_usd_per_million_tokens: 2, output_usd_per_million_tokens: 8}]"
	entries, err := ParseModels([]byte(validGemini38))
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected gemini-3.8-flash allowed with builtin price: %v", err)
	}
}
