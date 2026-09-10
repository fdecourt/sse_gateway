package event

import (
	"fmt"
	"regexp"
	"strings"
)

// Router gère la construction et l'analyse syntaxique des clés de routage des événements.
type Router struct {
	template     string
	matcherRegex *regexp.Regexp
	tenantIdx    int
	appIdx       int
	topicIdx     int
}

// NewRouter initialise le routeur à partir d'un gabarit de routage (ex: tenant:{tenant}:app:{app}:topic:{topic}).
func NewRouter(template string) (*Router, error) {
	if template == "" {
		template = "tenant:{tenant}:app:{app}:topic:{topic}"
	}

	// Conversion du template en expression régulière avec groupes nommés
	pattern := regexp.QuoteMeta(template)
	pattern = strings.ReplaceAll(pattern, `\{tenant\}`, `(?P<tenant>[^:]+)`)
	pattern = strings.ReplaceAll(pattern, `\{app\}`, `(?P<app>[^:]+)`)
	pattern = strings.ReplaceAll(pattern, `\{topic\}`, `(?P<topic>.+)`)
	pattern = "^" + pattern + "$"

	rx, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("compilation du gabarit de routage échouée (%s): %w", template, err)
	}

	r := &Router{
		template:     template,
		matcherRegex: rx,
		tenantIdx:    rx.SubexpIndex("tenant"),
		appIdx:       rx.SubexpIndex("app"),
		topicIdx:     rx.SubexpIndex("topic"),
	}

	return r, nil
}

// sanitizeKeyPart neutralise les éventuels caractères ':' pour empêcher toute collision multi-tenant.
func sanitizeKeyPart(s string) string {
	return strings.ReplaceAll(s, ":", "_")
}

// BuildKey construit la clé de routage unifiée à partir des trois composantes canoniques.
// Les séparateurs ':' dans tenantID et appID sont neutralisés pour garantir l'isolation.
func (r *Router) BuildKey(tenantID, appID, topicID string) string {
	res := strings.ReplaceAll(r.template, "{tenant}", sanitizeKeyPart(tenantID))
	res = strings.ReplaceAll(res, "{app}", sanitizeKeyPart(appID))
	res = strings.ReplaceAll(res, "{topic}", topicID)
	return res
}

// ParseKey extrait le tenant, l'app et le topic depuis une clé de routage reçue.
// Réservé pour la reconstruction contextuelle lors de la reprise sur en-tête Last-Event-ID.
func (r *Router) ParseKey(key string) (tenantID, appID, topicID string, ok bool) {
	matches := r.matcherRegex.FindStringSubmatch(key)
	if matches == nil {
		return "", "", "", false
	}

	if r.tenantIdx > 0 && r.tenantIdx < len(matches) {
		tenantID = matches[r.tenantIdx]
	}
	if r.appIdx > 0 && r.appIdx < len(matches) {
		appID = matches[r.appIdx]
	}
	if r.topicIdx > 0 && r.topicIdx < len(matches) {
		topicID = matches[r.topicIdx]
	}

	return tenantID, appID, topicID, true
}
