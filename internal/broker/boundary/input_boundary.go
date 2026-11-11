package boundary

import (
	"errors"
	"strings"
)

// ErrRemoteMediaForbidden is returned when remote media URLs are present.
var ErrRemoteMediaForbidden = errors.New("remote media URLs are forbidden in the executor")

const RemoteMessage = "remote media URLs are forbidden in the executor"

// InlineImage reports whether url represents an inline image.
// url can be a string ("data:image/...") or a map containing "url" (and optional "detail").
func InlineImage(val any) bool {
	switch v := val.(type) {
	case string:
		return strings.HasPrefix(v, "data:image/")
	case map[string]any:
		for k := range v {
			if k != "url" && k != "detail" {
				return false
			}
		}
		urlVal, ok := v["url"].(string)
		return ok && strings.HasPrefix(urlVal, "data:image/")
	default:
		return false
	}
}

// RemoteInputError traverses a JSON data structure and returns an error if provider-fetched media is detected.
func RemoteInputError(val any) error {
	switch v := val.(type) {
	case []any:
		for _, item := range v {
			if err := RemoteInputError(item); err != nil {
				return err
			}
		}
	case map[string]any:
		if imgURL, exists := v["image_url"]; exists && imgURL != nil {
			if !InlineImage(imgURL) {
				return ErrRemoteMediaForbidden
			}
		}
		for _, key := range []string{"file_url", "file_uri", "fileUri"} {
			if fVal, exists := v[key]; exists && fVal != nil {
				return ErrRemoteMediaForbidden
			}
		}
		if source, exists := v["source"]; exists {
			if smap, ok := source.(map[string]any); ok {
				if t, ok := smap["type"].(string); ok && t == "url" {
					return ErrRemoteMediaForbidden
				}
			}
		}
		for _, item := range v {
			if err := RemoteInputError(item); err != nil {
				return err
			}
		}
	}
	return nil
}
