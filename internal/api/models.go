package api

import "time"

// HealthResponse modélise le statut de santé renvoyé par /healthz ou /readyz.
type HealthResponse struct {
	Status    string            `json:"status"`
	Service   string            `json:"service"`
	Instance  string            `json:"instance_id,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
	UptimeSec int64             `json:"uptime_seconds"`
	Details   map[string]string `json:"details,omitempty"`
}

// ErrorResponse modélise les erreurs standard renvoyées au format JSON.
type ErrorResponse struct {
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
}
