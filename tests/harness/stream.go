package harness

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"sse-gateway/internal/hub"
)

// maxFrameBytes borne la taille d'une trame lue par le banc d'essai.
const maxFrameBytes = 16 << 20

// Frame est une trame Server-Sent Events décodée.
type Frame struct {
	Event string
	ID    string
	Data  string
}

// Stream maintient un flux SSE ouvert et publie les trames décodées.
// Les commentaires SSE — dont les battements de cœur — sont ignorés.
type Stream struct {
	frames chan Frame
	header http.Header

	cancel    context.CancelFunc
	body      io.ReadCloser
	closeOnce sync.Once
}

// HandshakeError signale un flux refusé à l'admission, en conservant le code
// HTTP afin que les tests puissent affirmer sur le motif du refus.
type HandshakeError struct {
	StatusCode int
	Body       string
}

func (e *HandshakeError) Error() string {
	return fmt.Sprintf("handshake SSE refusé (HTTP %d): %s", e.StatusCode, e.Body)
}

// Open établit le flux SSE et démarre le décodage en arrière-plan. Un flux sain
// ne se termine jamais de lui-même : l'appelant doit systématiquement le fermer.
func Open(gatewayURL, ticket string, buffer int) (*Stream, error) {
	ctx, cancel := context.WithCancel(context.Background())

	endpoint := fmt.Sprintf("%s/v1/events?ticket=%s",
		strings.TrimRight(gatewayURL, "/"), url.QueryEscape(ticket))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header.Set("Accept", "text/event-stream")

	// Aucune échéance globale : elle couperait le flux au lieu de le maintenir.
	resp, err := (&http.Client{Timeout: 0}).Do(req)
	if err != nil {
		cancel()
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		cancel()
		return nil, &HandshakeError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(body))}
	}

	s := &Stream{
		frames: make(chan Frame, buffer),
		header: resp.Header,
		cancel: cancel,
		body:   resp.Body,
	}
	go s.decode()
	return s, nil
}

// Header expose les en-têtes de la réponse d'admission.
func (s *Stream) Header() http.Header { return s.header }

// Frames expose le flux brut de trames, pour les consommateurs qui vident la
// file en continu afin de ne pas être classés clients lents.
func (s *Stream) Frames() <-chan Frame { return s.frames }

func (s *Stream) decode() {
	defer close(s.frames)

	scanner := bufio.NewScanner(s.body)
	scanner.Buffer(make([]byte, 0, 64<<10), maxFrameBytes)

	var current Frame
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "":
			if current != (Frame{}) {
				select {
				case s.frames <- current:
				default: // banc d'essai saturé : la trame est abandonnée
				}
			}
			current = Frame{}
		case strings.HasPrefix(line, ":"):
			// Commentaire SSE (battement de cœur).
		case strings.HasPrefix(line, "event: "):
			current.Event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "id: "):
			current.ID = strings.TrimPrefix(line, "id: ")
		case strings.HasPrefix(line, "data: "):
			current.Data = strings.TrimPrefix(line, "data: ")
		}
	}
}

// Next rend la prochaine trame, ou false si le délai expire ou le flux se ferme.
func (s *Stream) Next(timeout time.Duration) (Frame, bool) {
	select {
	case f, ok := <-s.frames:
		return f, ok
	case <-time.After(timeout):
		return Frame{}, false
	}
}

// Await attend une trame du type demandé, en écartant les autres.
func (s *Stream) Await(eventType string, timeout time.Duration) (Frame, bool) {
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return Frame{}, false
		}
		f, ok := s.Next(remaining)
		if !ok {
			return Frame{}, false
		}
		if f.Event == eventType {
			return f, true
		}
	}
}

// Silent consomme le flux pendant la fenêtre donnée et rend les types de trames
// applicatives reçues. Une tranche vide atteste qu'aucune diffusion n'a eu lieu.
func (s *Stream) Silent(window time.Duration) []string {
	var seen []string
	deadline := time.Now().Add(window)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return seen
		}
		f, ok := s.Next(remaining)
		if !ok {
			return seen
		}
		if f.Event != "" && f.Event != hub.ConnectedEventType {
			seen = append(seen, f.Event)
		}
	}
}

// AwaitConnected consomme l'accusé de connexion émis à l'admission.
func (s *Stream) AwaitConnected(timeout time.Duration) (Frame, bool) {
	return s.Await(hub.ConnectedEventType, timeout)
}

// Close ferme le flux et libère la connexion.
func (s *Stream) Close() {
	s.closeOnce.Do(func() {
		s.cancel()
		if s.body != nil {
			s.body.Close()
		}
	})
}
