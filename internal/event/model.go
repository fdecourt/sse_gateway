package event

import (
	"encoding/json"
	"time"
)

// DecryptedEventPayload représente le payload final diffusé aux clients SSE après déchiffrement réussi.
type DecryptedEventPayload struct {
	EventID      string          `json:"event_id"`
	TenantID     string          `json:"tenant_id"`
	AppID        string          `json:"app_id"`
	TopicID      string          `json:"topic_id"`
	Type         string          `json:"type"`
	EntityID     string          `json:"entity_id,omitempty"`
	Version      int64           `json:"version"`
	OriginUserID string          `json:"origin_user_id,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
	Data         json.RawMessage `json:"data"` // JSON en clair obtenu après déchiffrement AES
}
