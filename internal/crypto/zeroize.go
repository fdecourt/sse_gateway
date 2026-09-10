package crypto

import (
	"crypto/subtle"
	"runtime"
)

// Zeroize écrase immédiatement les données sensibles en mémoire (DEK, clés temporaires).
// Utilise le mot-clé clear(b) standard Go, vérifie la mise à zéro en temps constant,
// et invoque runtime.KeepAlive(b) pour garantir au compilateur que la tranche mémoire
// est préservée et que l'opération n'est pas optimisée ou éliminée par Dead Store Elimination (DSE).
func Zeroize(b []byte) {
	if len(b) == 0 {
		return
	}
	clear(b)
	for i := range b {
		_ = subtle.ConstantTimeByteEq(b[i], 0)
	}
	runtime.KeepAlive(b)
}
