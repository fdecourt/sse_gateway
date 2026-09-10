package tests

import (
	"fmt"
	"testing"

	"sse-gateway/internal/event"
	"sse-gateway/internal/hub"
)

func BenchmarkHubRegister(b *testing.B) {
	h := hub.NewHub(256, hub.LimitsConfig{}, nil)
	client := hub.NewClient("bench-c", "u", "t", []string{"rKey"}, 100, hub.SlowPolicyDropOldest, nil)
	topics := []string{"tenant:t:app:a:topic:bench"}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = h.Register(client, topics)
		h.Unregister(client)
	}
}

func BenchmarkHubLookup(b *testing.B) {
	h := hub.NewHub(256, hub.LimitsConfig{}, nil)
	topics := []string{"tenant:t:app:a:topic:lookup"}
	for i := 0; i < 100; i++ {
		c := hub.NewClient(fmt.Sprintf("c%d", i), "u", "t", topics, 10, hub.SlowPolicyDisconnect, nil)
		_ = h.Register(c, topics)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = h.HasSubscribers("tenant:t:app:a:topic:lookup")
	}
}

func benchmarkFanoutN(b *testing.B, n int) {
	h := hub.NewHub(256, hub.LimitsConfig{}, nil)
	topic := "tenant:t:app:a:topic:fanout"
	topics := []string{topic}

	for i := 0; i < n; i++ {
		c := hub.NewClient(fmt.Sprintf("c%d", i), "u", "t", topics, b.N+10, hub.SlowPolicyDropOldest, nil)
		_ = h.Register(c, topics)
	}

	frame := hub.NewDataFrame("msg", "1", []byte(`{"event":"test"}`))

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = h.ConditionalBroadcast(topic, func() (*hub.Frame, error) {
			return frame, nil
		})
	}
}

func BenchmarkFanout10(b *testing.B) {
	benchmarkFanoutN(b, 10)
}

func BenchmarkFanout100(b *testing.B) {
	benchmarkFanoutN(b, 100)
}

func BenchmarkFanout1000(b *testing.B) {
	benchmarkFanoutN(b, 1000)
}

func BenchmarkFrameShared(b *testing.B) {
	payload := []byte(`{"status":"active","metrics":{"cpu":12,"mem":42}}`)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = hub.NewDataFrame("update", "100", payload)
	}
}

func BenchmarkEventRouting(b *testing.B) {
	r, _ := event.NewRouter("tenant:{tenant}:app:{app}:topic:{topic}")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		key := r.BuildKey("tenant-42", "app-dashboard", "realtime-widgets")
		_, _, _, _ = r.ParseKey(key)
	}
}
