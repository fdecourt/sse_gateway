package logging

import (
	"context"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
)

// Config regroupe les paramètres du système de logs.
type Config struct {
	Level             string // debug, info, warn, error
	Format            string // json, text
	IncludeSource     bool
	RedactQueryString bool
}

// RedactURL masque les paramètres sensibles (ticket, token, secret, password) dans une URL ou requête.
func RedactURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "[URL MALFORMÉE]"
	}

	q := u.Query()
	for key := range q {
		lower := strings.ToLower(key)
		if lower == "ticket" || lower == "token" || lower == "secret" || lower == "password" || lower == "key" {
			q.Set(key, "REDACTED")
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// NewLogger instancie un slog.Logger configuré selon les exigences de sécurité.
func NewLogger(cfg Config) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(cfg.Level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level:       lvl,
		AddSource:   cfg.IncludeSource,
		ReplaceAttr: makeSanitizeAttr(cfg),
	}

	var w io.Writer = os.Stdout
	var handler slog.Handler

	if strings.ToLower(cfg.Format) == "text" {
		handler = slog.NewTextHandler(w, opts)
	} else {
		handler = slog.NewJSONHandler(w, opts)
	}

	return slog.New(handler)
}

// makeSanitizeAttr configure le filtre des attributs sensibles selon la configuration.
func makeSanitizeAttr(cfg Config) func(groups []string, a slog.Attr) slog.Attr {
	return func(groups []string, a slog.Attr) slog.Attr {
		lowerKey := strings.ToLower(a.Key)
		switch lowerKey {
		case "ticket", "token", "dek", "plaintext", "secret", "password", "authorization":
			return slog.String(a.Key, "[MASQUÉ]")
		case "query", "url", "uri", "request_uri":
			if cfg.RedactQueryString {
				if strVal, ok := a.Value.Any().(string); ok {
					return slog.String(a.Key, RedactURL(strVal))
				}
			}
		}
		return a
	}
}

type contextKey string

const (
	// TraceIDKey permet d'attacher un identifiant de corrélation distribué au contexte.
	TraceIDKey contextKey = "trace_id"
)

// WithContext enrichit le logger avec les attributs de traçabilité (trace_id) s'ils sont présents dans le contexte.
func WithContext(ctx context.Context, logger *slog.Logger) *slog.Logger {
	if ctx == nil || logger == nil {
		return logger
	}
	if traceID, ok := ctx.Value(TraceIDKey).(string); ok && traceID != "" {
		return logger.With("trace_id", traceID)
	}
	return logger
}
