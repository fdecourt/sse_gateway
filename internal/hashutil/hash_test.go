package hashutil_test

import (
	"testing"

	"sse-gateway/internal/hashutil"
)

func TestFnv32a_Determinism(t *testing.T) {
	h1 := hashutil.Fnv32a("tenant:1:app:2:topic:3")
	h2 := hashutil.Fnv32a("tenant:1:app:2:topic:3")

	if h1 != h2 {
		t.Errorf("le hachage FNV32a doit être déterministe: %d != %d", h1, h2)
	}
}

func TestShardIndex_Bounds(t *testing.T) {
	numShards := 256
	for _, key := range []string{"orders", "notifications", "chat", "tenant:acme:app:crm:topic:live"} {
		idx := hashutil.ShardIndex(key, numShards)
		if idx < 0 || idx >= numShards {
			t.Errorf("index de shard hors bornes [0, %d[: %d", numShards, idx)
		}
	}

	// Cas limite count <= 1
	if idx := hashutil.ShardIndex("key", 1); idx != 0 {
		t.Errorf("attendu 0 pour count=1, obtenu: %d", idx)
	}
}
