//go:build !linux

package crypto

// HardenProcess est une implémentation sans effet (no-op) sur les systèmes non-Linux (Windows, macOS).
func HardenProcess() {
	// Les primitives prctl et rlimit Linux ne s'appliquent pas ici.
}
