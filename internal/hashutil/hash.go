package hashutil

import "hash/fnv"

// Fnv32a calcule le hash FNV-1a 32 bits d'une chaîne UTF-8.
func Fnv32a(s string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return h.Sum32()
}

// ShardIndex calcule l'indice de partition (shard ou lane) borné entre 0 et count-1.
func ShardIndex(key string, count int) int {
	if count <= 1 {
		return 0
	}
	return int(Fnv32a(key) % uint32(count))
}
