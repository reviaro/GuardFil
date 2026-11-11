package budget

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"

	"go.yaml.in/yaml/v3"
)

// The owner's model list: models the brokers may use beyond the built-in ones,
// each with its price, so the ledger can still bound every request's cost.
//
//	# ~/.config/guardfil/models.yaml (owner-only, like the API keys)
//	models:
//	  - {provider: openai, model: gpt-6-sol, input_usd_per_million_tokens: 3, output_usd_per_million_tokens: 12}
//
// Prices are whole US dollars per million tokens (the ledger counts integer
// micro-dollars per token); round a cheaper price up to 1, which overestimates
// cost. Once a model has been used, keep its entry and price: the ledger
// re-derives every past settlement from it at startup.

// ModelEntry is one owner-listed model.
type ModelEntry struct {
	Provider string `yaml:"provider"`
	Model    string `yaml:"model"`
	Input    int    `yaml:"input_usd_per_million_tokens"`
	Output   int    `yaml:"output_usd_per_million_tokens"`
}

const (
	maxModelsFileBytes = 64 << 10
	maxModelEntries    = 256
	maxPricePerMTok    = 10_000
)

var modelName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// providerTier is the service tier each provider reports for standard requests.
var providerTier = map[string]string{"openai": "default", "gemini": "default", "anthropic": "standard"}

// BuiltinModelProvider maps each built-in model to its provider.
var BuiltinModelProvider = map[string]string{
	PinnedModel:             "openai",
	"gemini-3.8-flash":      "gemini",
	"gemini-3.6-flash":      "gemini",
	"gemini-3.5-flash-lite": "gemini",
	"claude-sonnet-5-5":     "anthropic",
}

// ProviderModels lists the models each provider's broker accepts: the built-in
// ones plus the owner's list once LoadModels has run.
var ProviderModels = map[string]map[string]bool{
	"openai":    {PinnedModel: true},
	"gemini":    {"gemini-3.8-flash": true, "gemini-3.6-flash": true, "gemini-3.5-flash-lite": true},
	"anthropic": {"claude-sonnet-5-5": true},
}

// AllowedModel reports whether provider's broker may use model.
func AllowedModel(provider, model string) bool {
	_, priced := ModelRates[model]
	return priced && ProviderModels[provider][model]
}

// NotAllowedMessage explains how to allow a model the brokers refused.
func NotAllowedMessage(provider, model string) string {
	return fmt.Sprintf("model %q is not in GuardFil's model list for %s; add it with its price to ~/.config/guardfil/models.yaml", model, provider)
}

// DefaultModelsPath is the owner's model list next to the API keys.
func DefaultModelsPath() string {
	return filepath.Join(os.Getenv("HOME"), ".config", "guardfil", "models.yaml")
}

// LoadModels adds the owner's model list at path to ModelRates and
// ProviderModels. A missing file leaves the built-in models only. It must run
// before any broker or ledger starts (it is not safe for concurrent use).
func LoadModels(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("model list: %w", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 || !ok || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("model list %s must be a regular file owned by you with mode 0600", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("model list: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxModelsFileBytes+1))
	if err != nil {
		return fmt.Errorf("model list: %w", err)
	}
	entries, err := ParseModels(raw)
	if err != nil {
		return fmt.Errorf("model list %s: %w", path, err)
	}
	for _, e := range entries {
		ModelRates[e.Model] = ModelRate{InputRateMicros: e.Input, OutputRateMicros: e.Output, ServiceTier: providerTier[e.Provider]}
		ProviderModels[e.Provider][e.Model] = true
	}
	return nil
}

// ParseModels validates a model list. A built-in model may be listed only with
// its built-in price.
func ParseModels(raw []byte) ([]ModelEntry, error) {
	if len(raw) > maxModelsFileBytes {
		return nil, errors.New("too large")
	}
	var doc struct {
		Models []ModelEntry `yaml:"models"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(doc.Models) > maxModelEntries {
		return nil, fmt.Errorf("at most %d models", maxModelEntries)
	}
	seen := map[string]bool{}
	for _, e := range doc.Models {
		if _, ok := providerTier[e.Provider]; !ok {
			return nil, fmt.Errorf("model %q: provider must be openai, anthropic or gemini", e.Model)
		}
		if !modelName.MatchString(e.Model) {
			return nil, fmt.Errorf("model %q: use the provider's model id (lower-case letters, digits, . _ -)", e.Model)
		}
		if seen[e.Model] {
			return nil, fmt.Errorf("model %q is listed twice", e.Model)
		}
		seen[e.Model] = true
		if e.Input < 1 || e.Output < 1 || e.Input > maxPricePerMTok || e.Output > maxPricePerMTok {
			return nil, fmt.Errorf("model %q: prices are whole USD per million tokens, 1 to %d (round a cheaper price up to 1)", e.Model, maxPricePerMTok)
		}
		if p, builtin := BuiltinModelProvider[e.Model]; builtin {
			if e.Provider != p {
				return nil, fmt.Errorf("model %q is built in for %s", e.Model, p)
			}
			r := ModelRates[e.Model]
			if r.InputRateMicros != e.Input || r.OutputRateMicros != e.Output {
				return nil, fmt.Errorf("model %q is built in at %d/%d; its price can't change because the ledger re-derives past settlements from it", e.Model, r.InputRateMicros, r.OutputRateMicros)
			}
		}
	}
	return doc.Models, nil
}
