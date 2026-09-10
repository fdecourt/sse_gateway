//go:build linux

package crypto

import (
	"golang.org/x/sys/unix"
	"log"
)

// HardenProcess applique les durcissements système critiques sous Linux :
// 1. Désactivation des core dumps via PR_SET_DUMPABLE (atténuation fuite mémoire clé DEK)
// 2. Prévention de l'attachement ptrace non autorisé (anti-débogage mémoire)
func HardenProcess() {
	// Désactiver PR_SET_DUMPABLE empêche les core dumps non sollicités et l'accès /proc/self/mem par un tiers
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		log.Printf("[SECURITY WARNING] Échec de l'application de PR_SET_DUMPABLE: %v", err)
	}

	// Limiter la taille des core dumps à 0
	var rlimit unix.Rlimit
	rlimit.Cur = 0
	rlimit.Max = 0
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &rlimit); err != nil {
		log.Printf("[SECURITY WARNING] Échec de la désactivation RLIMIT_CORE: %v", err)
	}
}
