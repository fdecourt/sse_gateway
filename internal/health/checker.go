package health

import "context"

// Checker définit l'interface minimale d'une sonde de disponibilité (Readiness probe).
// Permet de respecter le principe ISP (Interface Segregation Principle) côté API HTTP.
type Checker interface {
	Name() string
	Check(ctx context.Context) error
}
