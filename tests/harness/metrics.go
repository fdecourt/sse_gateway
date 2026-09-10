package harness

import (
	"bufio"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Noms des séries Prometheus sur lesquelles le banc d'essai affirme. Les
// déclarer ici évite d'éparpiller des littéraux dans les tests et les outils.
const (
	MetricEventsDecrypted    = "sse_events_decrypted_total"
	MetricDecryptErrors      = "sse_decrypt_errors_total"
	MetricEventsNoSubscriber = "sse_events_no_subscriber_total"
	MetricFanoutRecipients   = "sse_fanout_recipients_total"
	MetricConnectionsActive  = "sse_connections_active"
	MetricSlowClients        = "sse_slow_clients_total"
	MetricCryptoDuration     = "sse_crypto_duration_seconds"
	MetricProcessingDuration = "sse_event_processing_duration_seconds"
)

// Snapshot est un relevé instantané de l'exposition Prometheus, indexé par
// série complète (nom et étiquettes comprises).
type Snapshot map[string]float64

// Scrape relève /metrics sur la passerelle.
func Scrape(gatewayURL string) (Snapshot, error) {
	resp, err := http.Get(strings.TrimRight(gatewayURL, "/") + "/metrics")
	if err != nil {
		return nil, fmt.Errorf("relevé de /metrics: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("/metrics a répondu %d", resp.StatusCode)
	}

	out := make(Snapshot)
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		series, rawValue, found := strings.Cut(line, " ")
		if !found {
			continue
		}
		if value, err := strconv.ParseFloat(rawValue, 64); err == nil {
			out[series] = value
		}
	}
	return out, scanner.Err()
}

// Delta rend la variation d'un compteur entre deux relevés.
func (s Snapshot) Delta(before Snapshot, series string) float64 {
	return s[series] - before[series]
}

// MeanMillis rend la durée moyenne, en millisecondes, observée par un
// histogramme entre deux relevés. Elle vaut 0 si aucune mesure n'a été prise.
func (s Snapshot) MeanMillis(before Snapshot, histogram string) float64 {
	count := s.Delta(before, histogram+"_count")
	if count <= 0 {
		return 0
	}
	return s.Delta(before, histogram+"_sum") / count * 1000
}
