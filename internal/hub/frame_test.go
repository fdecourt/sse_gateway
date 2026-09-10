package hub

import (
	"bytes"
	"testing"
)

func TestFrame_SanitizeHeaderPreventsInjection(t *testing.T) {
	maliciousEventType := "order.created\r\nevent: fake.admin.event\r\ndata: {\"pwned\":true}\r\n\r\n"
	maliciousEventID := "12345\nevent: injected"
	payload := []byte("{\"status\":\"ok\"}")

	frame := NewDataFrame(maliciousEventType, maliciousEventID, payload)

	// La trame produite ne doit comporter AUCUN saut de ligne CRLF ou LF dans l'en-tête de l'événement
	// et ne doit contenir qu'une seule séquence de fin de trame "\n\n"
	dataStr := string(frame.Data)

	// Doit contenir les deux newlines finaux exactement une fois à la fin
	if !bytes.HasSuffix(frame.Data, []byte("\n\n")) {
		t.Fatalf("la trame doit se terminer par \\n\\n")
	}

	// Il ne doit y avoir aucune injection d'en-tête intermédiaire
	if bytes.Count(frame.Data, []byte("fake.admin.event")) != 1 {
		t.Fatalf("l'événement injecté doit être aplati")
	}

	// Aucun caractère \r ne doit persister
	if bytes.Contains(frame.Data, []byte("\r")) {
		t.Fatalf("caractère \\r non nettoyé dans la trame")
	}

	// Vérification de la structure attendue
	expectedPrefix := "event: order.createdevent: fake.admin.eventdata: {\"pwned\":true}\nid: 12345event: injected\ndata: {\"status\":\"ok\"}\n\n"
	if dataStr != expectedPrefix {
		t.Errorf("trame assainie inattendue:\nGot:  %q\nWant: %q", dataStr, expectedPrefix)
	}
}

func TestFrame_NewHeartbeatFrame(t *testing.T) {
	f1 := NewHeartbeatFrame("")
	if string(f1.Data) != ": ping\n\n" {
		t.Errorf("attendu ': ping\\n\\n', obtenu %q", string(f1.Data))
	}

	f2 := NewHeartbeatFrame("keepalive")
	if string(f2.Data) != ": keepalive\n\n" {
		t.Errorf("attendu ': keepalive\\n\\n', obtenu %q", string(f2.Data))
	}

	f3 := NewHeartbeatFrame(": custom")
	if string(f3.Data) != ": custom\n\n" {
		t.Errorf("attendu ': custom\\n\\n', obtenu %q", string(f3.Data))
	}
}
