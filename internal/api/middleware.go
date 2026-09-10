package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"sse-gateway/internal/logging"
)

// isSafeTraceID vérifie que l'identifiant de trace respecte les bornes strictes de sécurité
// (longueur entre 1 et 64 caractères, uniquement alphanumérique, tiret ou underscore)
// afin de prévenir toute injection de chaîne abusive ou gonflement des logs.
func isSafeTraceID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// TraceMiddleware extrait ou génère un identifiant de corrélation (X-Request-ID ou X-Trace-ID)
// assaini et l'attache au contexte de la requête ainsi qu'à l'en-tête de réponse.
func TraceMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		traceID := r.Header.Get("X-Request-ID")
		if traceID == "" {
			traceID = r.Header.Get("X-Trace-ID")
		}
		if !isSafeTraceID(traceID) {
			b := make([]byte, 16)
			_, _ = rand.Read(b)
			traceID = hex.EncodeToString(b)
		}

		ctx := context.WithValue(r.Context(), logging.TraceIDKey, traceID)
		w.Header().Set("X-Request-ID", traceID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// responseWriterInterceptor capture le code HTTP de statut pour le logging d'accès.
type responseWriterInterceptor struct {
	http.ResponseWriter
	statusCode int
	bytesCount int
}

func (w *responseWriterInterceptor) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *responseWriterInterceptor) Write(b []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytesCount += n
	return n, err
}

func (w *responseWriterInterceptor) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// SecurityHeadersMiddleware applique les en-têtes HTTP de sécurité recommandés.
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// RecoveryMiddleware intercepte les paniques inattendues et prévient l'arrêt brutal du serveur.
func RecoveryMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					stack := string(debug.Stack())
					reqLogger := logging.WithContext(r.Context(), logger)
					reqLogger.Error("Panique HTTP interceptée",
						"error", rec,
						"stack", stack,
						"path", logging.RedactURL(r.URL.String()),
					)
					respondError(w, http.StatusInternalServerError, "erreur interne du serveur", "une exception inattendue est survenue")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// LoggerMiddleware journalise les requêtes HTTP avec masquage systématique des secrets et corrélation de trace.
func LoggerMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			interceptor := &responseWriterInterceptor{ResponseWriter: w}

			next.ServeHTTP(interceptor, r)

			duration := time.Since(start)
			status := interceptor.statusCode
			if status == 0 {
				status = http.StatusOK
			}

			reqLogger := logging.WithContext(r.Context(), logger)
			reqLogger.Info("Requête HTTP",
				"method", r.Method,
				"path", logging.RedactURL(r.URL.String()),
				"status", status,
				"bytes", interceptor.bytesCount,
				"duration_ms", duration.Milliseconds(),
				"remote_addr", r.RemoteAddr,
			)
		})
	}
}

// RateLimitMiddleware limite le débit des requêtes par adresse IP cliente.
func RateLimitMiddleware(limiter *IPRateLimiter, trustProxy bool, trustedCIDRs []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := extractClientIP(r, trustProxy, trustedCIDRs)
			l := limiter.GetLimiter(clientIP)
			if !l.Allow() {
				respondError(w, http.StatusTooManyRequests, "limite de débit dépassée", "trop de requêtes soumises, veuillez réitérer ultérieurement")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
