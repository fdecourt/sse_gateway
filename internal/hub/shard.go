package hub

import (
	"sync"
)

// Shard représente une partition isolée du Hub disposant de son propre verrou RWMutex.
// Règle absolue : aucun travail lourd (crypto, sérialisation JSON, I/O réseau) sous verrou.
type Shard struct {
	mu      sync.RWMutex
	topics  map[string]map[string]*Client // routingKey -> clientID -> *Client
	clients map[string]*Client            // clientID -> *Client
}

// NewShard instancie une partition du Hub.
func NewShard() *Shard {
	return &Shard{
		topics:  make(map[string]map[string]*Client),
		clients: make(map[string]*Client),
	}
}

// Register attache un client à une clé de routage spécifique.
func (s *Shard) Register(routingKey string, client *Client) {
	s.mu.Lock()
	defer s.mu.Unlock()

	clientMap, ok := s.topics[routingKey]
	if !ok {
		clientMap = make(map[string]*Client)
		s.topics[routingKey] = clientMap
	}
	clientMap[client.ID] = client
	s.clients[client.ID] = client
}

// Unregister détache un client d'une clé de routage.
func (s *Shard) Unregister(routingKey string, clientID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if clientMap, ok := s.topics[routingKey]; ok {
		delete(clientMap, clientID)
		if len(clientMap) == 0 {
			delete(s.topics, routingKey)
		}
	}
	delete(s.clients, clientID)
}

// HasSubscribers vérifie en O(1) sous RLock si au moins un client local est abonné au topic.
func (s *Shard) HasSubscribers(routingKey string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	clientMap, ok := s.topics[routingKey]
	return ok && len(clientMap) > 0
}

// GetRecipients extrait une copie instantanée (snapshot) des clients abonnés sous RLock.
// La diffusion réseau effective s'exécute ainsi intégralement hors verrouillage.
func (s *Shard) GetRecipients(routingKey string) []*Client {
	s.mu.RLock()
	defer s.mu.RUnlock()

	clientMap, ok := s.topics[routingKey]
	if !ok || len(clientMap) == 0 {
		return nil
	}

	recipients := make([]*Client, 0, len(clientMap))
	for _, c := range clientMap {
		recipients = append(recipients, c)
	}
	return recipients
}

// GetAllClients extrait tous les clients hébergés sur ce shard (notamment pour les heartbeats).
func (s *Shard) GetAllClients() []*Client {
	s.mu.RLock()
	defer s.mu.RUnlock()

	all := make([]*Client, 0, len(s.clients))
	for _, c := range s.clients {
		all = append(all, c)
	}
	return all
}

// InvalidateUser ferme et retire tous les clients correspondant au user et tenant ciblés.
func (s *Shard) InvalidateUser(tenantID, userID string) []*Client {
	s.mu.Lock()
	defer s.mu.Unlock()

	var matched []*Client
	for id, c := range s.clients {
		if c.TenantID == tenantID && c.UserID == userID {
			matched = append(matched, c)
			delete(s.clients, id)
		}
	}

	for _, c := range matched {
		for rKey, clientMap := range s.topics {
			delete(clientMap, c.ID)
			if len(clientMap) == 0 {
				delete(s.topics, rKey)
			}
		}
	}

	return matched
}
