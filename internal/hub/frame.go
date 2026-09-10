package hub

import (
	"bytes"
	"fmt"
	"strings"
)

// ConnectedEventType est le type de la trame d'accueil émise dès l'admission du
// client. Les consommateurs s'en servent pour distinguer l'accusé de connexion
// des événements applicatifs.
const ConnectedEventType = "connected"

// Frame représente une trame SSE immuable et pré-sérialisée partagée par tous les abonnés.
// Une seule trame est allouée en mémoire quel que soit le nombre de clients destinataires (fan-out zéro copie).
type Frame struct {
	Data []byte
}

// sanitizeHeader élimine tout caractère \r ou \n pour prévenir toute injection de trames ou champs SSE.
func sanitizeHeader(s string) string {
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	return strings.TrimSpace(s)
}

// NewDataFrame construit une trame standard de données SSE (event: message, id, data).
// Les champs eventType et eventID sont nettoyés pour prévenir toute injection d'en-tête SSE.
func NewDataFrame(eventType, eventID string, payload []byte) *Frame {
	cleanType := sanitizeHeader(eventType)
	cleanID := sanitizeHeader(eventID)

	var buf bytes.Buffer
	if cleanType != "" {
		buf.WriteString("event: ")
		buf.WriteString(cleanType)
		buf.WriteByte('\n')
	}
	if cleanID != "" {
		buf.WriteString("id: ")
		buf.WriteString(cleanID)
		buf.WriteByte('\n')
	}
	buf.WriteString("data: ")
	buf.Write(payload)
	buf.WriteString("\n\n")

	return &Frame{Data: buf.Bytes()}
}

// NewHeartbeatFrame construit une trame légère de battement de cœur SSE (: ping\n\n).
func NewHeartbeatFrame(comment string) *Frame {
	trimmed := strings.TrimSpace(comment)
	if trimmed == "" {
		return &Frame{Data: []byte(": ping\n\n")}
	}
	if !strings.HasPrefix(trimmed, ":") {
		trimmed = ": " + trimmed
	}
	return &Frame{Data: []byte(trimmed + "\n\n")}
}

// NewConnectedFrame construit la trame initiale envoyée au client lors de l'établissement de la connexion SSE.
func NewConnectedFrame(connectionID string, heartbeatSec int) *Frame {
	jsonPayload := fmt.Sprintf(`{"connection_id":%q,"heartbeat_seconds":%d}`, connectionID, heartbeatSec)
	return NewDataFrame(ConnectedEventType, "0", []byte(jsonPayload))
}
