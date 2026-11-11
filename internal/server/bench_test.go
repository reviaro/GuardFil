package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/reviaro/guardfil/internal/telemetry"
)

// BenchmarkServerShell is shell overhead only; it neither measures policy nor asserts an SLO.
func BenchmarkServerShell(b *testing.B) {
	h := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }), &telemetry.Counters{})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))
	}
}
