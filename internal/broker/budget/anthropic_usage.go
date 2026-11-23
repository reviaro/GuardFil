package budget

import (
	"encoding/json"
	"errors"
)

// DecodeProviderMessage preserves integer literals and rejects ambiguous
// receipts (duplicate keys or multiple JSON values). Never include provider
// data in an error returned to the agent.
func DecodeProviderMessage(raw []byte) (map[string]any, error) {
	if json.Valid(raw) {
		value, err := safeJSONDecode(raw)
		if msg, ok := value.(map[string]any); err == nil && ok {
			return msg, nil
		}
	}
	return nil, errors.New("invalid provider message")
}

func usageCount(fields map[string]any, key string, limit int, required bool) (int, bool) {
	v := fields[key]
	if v == nil {
		return 0, !required
	}
	var n int64
	switch value := v.(type) {
	case json.Number:
		var err error
		n, err = value.Int64()
		if err != nil {
			return 0, false
		}
	case int:
		n = int64(value)
	case int64:
		n = value
	default:
		return 0, false
	}
	if n < 0 || n > int64(limit) {
		return 0, false
	}
	return int(n), true
}

// AnthropicInputTokens returns the reported and price-weighted input counts.
// Cache totals are optional. A usable TTL breakdown permits the short-cache
// rate, otherwise the full cache-write total is charged at the longer rate.
func AnthropicInputTokens(usage map[string]any) (reported, billable int, err error) {
	input, inputOK := usageCount(usage, "input_tokens", MaxInputTokens, true)
	created, createdOK := usageCount(usage, "cache_creation_input_tokens", MaxInputTokens, false)
	read, readOK := usageCount(usage, "cache_read_input_tokens", MaxInputTokens, false)
	if !inputOK || !createdOK || !readOK {
		return 0, 0, errors.New("invalid Anthropic input token counts")
	}
	writes := 2 * created
	if split, ok := usage["cache_creation"].(map[string]any); ok {
		short, shortOK := usageCount(split, "ephemeral_5m_input_tokens", MaxInputTokens, false)
		long, longOK := usageCount(split, "ephemeral_1h_input_tokens", MaxInputTokens, false)
		if !shortOK || !longOK || short+long > created {
			return 0, 0, errors.New("invalid Anthropic cache breakdown")
		}
		if short+long == created {
			writes = (5*short+3)/4 + 2*long
		}
	} else if usage["cache_creation"] != nil {
		return 0, 0, errors.New("invalid Anthropic cache breakdown")
	}
	reported = input + created + read
	billable = input + writes + (read+9)/10
	if reported > MaxInputTokens || billable > MaxInputTokens {
		return 0, 0, errors.New("Anthropic input tokens exceed ledger bounds")
	}
	return reported, billable, nil
}

// AnthropicUsage keeps reported counts distinct from price-weighted ledger units.
type AnthropicUsage struct {
	InputTokens, BillableInputTokens, OutputTokens int
	ServiceTier                                    string
}

func ParseAnthropicUsage(fields map[string]any, defaultTier string) (AnthropicUsage, error) {
	input, billable, err := AnthropicInputTokens(fields)
	if err != nil {
		return AnthropicUsage{}, err
	}
	output, ok := usageCount(fields, "output_tokens", MaxOutputTokens, true)
	if !ok {
		return AnthropicUsage{}, errors.New("invalid Anthropic output token count")
	}
	tier := defaultTier
	if raw := fields["service_tier"]; raw != nil {
		tier, ok = raw.(string)
		if !ok || tier == "" {
			return AnthropicUsage{}, errors.New("invalid Anthropic service tier")
		}
	}
	return AnthropicUsage{InputTokens: input, BillableInputTokens: billable, OutputTokens: output, ServiceTier: tier}, nil
}

// AnthropicCountedInput validates the preflight evidence used to size a reservation.
func AnthropicCountedInput(raw []byte) (int, error) {
	msg, err := DecodeProviderMessage(raw)
	if err != nil {
		return 0, err
	}
	input, ok := usageCount(msg, "input_tokens", MaxInputTokens, true)
	if !ok {
		return 0, errors.New("invalid Anthropic input token count")
	}
	return input, nil
}
