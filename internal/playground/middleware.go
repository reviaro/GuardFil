package playground

import (
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
)

const (
	maxBodyBytes = 4 * 1024 * 1024 // 4 MiB
	cspHeader    = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)

func isAllowedHostname(host string) bool {
	if host == "" {
		return false
	}
	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}
	hostname = strings.TrimPrefix(hostname, "[")
	hostname = strings.TrimSuffix(hostname, "]")
	return hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1"
}

func hardeningMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", cspHeader)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")

		// Host header DNS-rebinding check
		if !isAllowedHostname(r.Host) {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}

		// Body limit
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

		// POST hardening checks
		if r.Method == http.MethodPost {
			ct := r.Header.Get("Content-Type")
			mediaType, _, err := mime.ParseMediaType(ct)
			if err != nil || mediaType != "application/json" {
				writeError(w, http.StatusUnsupportedMediaType, "unsupported media type")
				return
			}

			origin := r.Header.Get("Origin")
			if origin != "" {
				u, err := url.Parse(origin)
				if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
					writeError(w, http.StatusForbidden, "forbidden")
					return
				}
				origHost := u.Hostname()
				origHost = strings.TrimPrefix(origHost, "[")
				origHost = strings.TrimSuffix(origHost, "]")
				if origHost != "localhost" && origHost != "127.0.0.1" && origHost != "::1" {
					writeError(w, http.StatusForbidden, "forbidden")
					return
				}

				var hostPort string
				if _, p, err := net.SplitHostPort(r.Host); err == nil {
					hostPort = p
				}
				if u.Port() != hostPort {
					writeError(w, http.StatusForbidden, "forbidden")
					return
				}
			} else {
				if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
					writeError(w, http.StatusForbidden, "forbidden")
					return
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}
