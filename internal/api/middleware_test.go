package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"sse-gateway/internal/logging"
)

func TestSecurityHeadersMiddleware(t *testing.T) {
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeadersMiddleware(dummyHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	headers := rec.Header()
	if headers.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("en-tête X-Content-Type-Options invalide: %s", headers.Get("X-Content-Type-Options"))
	}
	if headers.Get("X-Frame-Options") != "DENY" {
		t.Errorf("en-tête X-Frame-Options invalide: %s", headers.Get("X-Frame-Options"))
	}
	if headers.Get("Content-Security-Policy") != "default-src 'none'" {
		t.Errorf("en-tête Content-Security-Policy invalide: %s", headers.Get("Content-Security-Policy"))
	}
	if headers.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("en-tête Referrer-Policy invalide: %s", headers.Get("Referrer-Policy"))
	}
}

func TestRecoveryMiddleware(t *testing.T) {
	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("panique de test simulée")
	})

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := RecoveryMiddleware(logger)(panicHandler)

	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	rec := httptest.NewRecorder()

	// Ne doit pas paniquer
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("attendu 500 Internal Server Error, obtenu %d", rec.Code)
	}
}

func TestTraceMiddleware(t *testing.T) {
	t.Run("génération automatique d'un trace ID", func(t *testing.T) {
		var ctxTraceID string
		dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if tid, ok := r.Context().Value(logging.TraceIDKey).(string); ok {
				ctxTraceID = tid
			}
			w.WriteHeader(http.StatusOK)
		})

		handler := TraceMiddleware(dummyHandler)
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		respHeader := rec.Header().Get("X-Request-ID")
		if respHeader == "" {
			t.Fatal("X-Request-ID manquant dans la réponse")
		}
		if ctxTraceID != respHeader {
			t.Fatalf("traceID dans le contexte (%s) != traceID dans le header (%s)", ctxTraceID, respHeader)
		}
	})

	t.Run("conservation de l'identifiant existant", func(t *testing.T) {
		existingID := "trace-custom-12345"
		var ctxTraceID string
		dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if tid, ok := r.Context().Value(logging.TraceIDKey).(string); ok {
				ctxTraceID = tid
			}
			w.WriteHeader(http.StatusOK)
		})

		handler := TraceMiddleware(dummyHandler)
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Request-ID", existingID)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Header().Get("X-Request-ID") != existingID {
			t.Fatalf("X-Request-ID modifié: attendu %s, obtenu %s", existingID, rec.Header().Get("X-Request-ID"))
		}
		if ctxTraceID != existingID {
			t.Fatalf("traceID dans le contexte: attendu %s, obtenu %s", existingID, ctxTraceID)
		}
	})

	t.Run("remplacement d'un identifiant surdimensionné ou malformé", func(t *testing.T) {
		oversizedID := "A-malicious-long-trace-id-that-exceeds-the-sixty-four-bytes-limit-and-must-be-regenerated-by-the-gateway-to-prevent-log-bloat"
		var ctxTraceID string
		dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if tid, ok := r.Context().Value(logging.TraceIDKey).(string); ok {
				ctxTraceID = tid
			}
			w.WriteHeader(http.StatusOK)
		})

		handler := TraceMiddleware(dummyHandler)
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Request-ID", oversizedID)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		newID := rec.Header().Get("X-Request-ID")
		if newID == oversizedID {
			t.Fatal("un identifiant > 64 caractères n'aurait pas dû être conservé")
		}
		if len(newID) != 32 { // 16 octets hex = 32 caractères
			t.Fatalf("longueur d'identifiant régénéré inattendue: %d", len(newID))
		}
		if ctxTraceID != newID {
			t.Fatalf("traceID dans contexte (%s) != traceID dans header (%s)", ctxTraceID, newID)
		}
	})
}
