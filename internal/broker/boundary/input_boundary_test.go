package boundary

import (
	"testing"
)

func TestForms(t *testing.T) {
	// Inline image with detail: low
	if err := RemoteInputError(map[string]any{
		"type": "image_url",
		"image_url": map[string]any{
			"url":    "data:image/png;base64,aGk=",
			"detail": "low",
		},
	}); err != nil {
		t.Fatalf("expected nil for valid inline image with detail, got %v", err)
	}

	// Remote http URL in image_url
	if err := RemoteInputError(map[string]any{
		"type": "image_url",
		"image_url": map[string]any{
			"url": "https://example.com/a.png",
		},
	}); err == nil {
		t.Fatalf("expected error for remote image url, got nil")
	}

	// file_url present
	if err := RemoteInputError(map[string]any{
		"type": "image_url",
		"image_url": map[string]any{
			"url":      "data:image/png;base64,aGk=",
			"file_url": "https://x",
		},
	}); err == nil {
		t.Fatalf("expected error for file_url, got nil")
	}

	// file_uri nested in parts
	if err := RemoteInputError([]any{
		map[string]any{
			"parts": []any{
				map[string]any{
					"file_data": map[string]any{
						"file_uri":  "https://example.com/a",
						"mime_type": "x",
					},
				},
			},
		},
	}); err == nil {
		t.Fatalf("expected error for nested file_uri, got nil")
	}

	// fileUri in camelCase
	if err := RemoteInputError(map[string]any{
		"fileData": map[string]any{
			"fileUri": "gs://bucket/a",
		},
	}); err == nil {
		t.Fatalf("expected error for fileUri, got nil")
	}

	// ordinary text with url
	if err := RemoteInputError(map[string]any{
		"text": "see https://example.com",
	}); err != nil {
		t.Fatalf("expected nil for ordinary text url, got %v", err)
	}

	// Anthropic remote media source type url
	if err := RemoteInputError(map[string]any{
		"type": "image",
		"source": map[string]any{
			"type": "url",
			"url":  "https://example.com/a",
		},
	}); err == nil {
		t.Fatalf("expected error for anthropic source url, got nil")
	}

	// Anthropic base64 inline image
	if err := RemoteInputError(map[string]any{
		"type": "image",
		"source": map[string]any{
			"type":       "base64",
			"media_type": "image/png",
			"data":       "aGVsbG8=",
		},
	}); err != nil {
		t.Fatalf("expected nil for anthropic base64 source, got %v", err)
	}
}
