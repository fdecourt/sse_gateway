package hub

import (
	"sync"
	"sync/atomic"
)

// SlowPolicy définit la politique de gestion de contre-pression lorsqu'un client est trop lent.
type SlowPolicy string

const (
	SlowPolicyDisconnect SlowPolicy = "disconnect"
	SlowPolicyDropOldest SlowPolicy = "drop_oldest"
	SlowPolicyDropNewest SlowPolicy = "drop_newest"
)

// Client représente une connexion SSE active et son canal d'envoi dédié.
type Client struct {
	ID           string
	UserID       string
	TenantID     string
	Topics       []string
	Send         chan *Frame
	SlowPolicy   SlowPolicy
	closed       atomic.Bool
	closeOnce    sync.Once
	closeNotify  chan struct{}
	unregistered atomic.Bool
	onSlow       func(c *Client)
}

// NewClient instancie un client SSE avec une file d'attente bornée.
func NewClient(id, userID, tenantID string, topics []string, queueSize int, policy SlowPolicy, onSlow func(c *Client)) *Client {
	if queueSize <= 0 {
		queueSize = 32
	}
	if policy == "" {
		policy = SlowPolicyDisconnect
	}

	return &Client{
		ID:          id,
		UserID:      userID,
		TenantID:    tenantID,
		Topics:      topics,
		Send:        make(chan *Frame, queueSize),
		SlowPolicy:  policy,
		closeNotify: make(chan struct{}),
		onSlow:      onSlow,
	}
}

// MarkUnregistered garantit l'idempotence du désenregistrement en retournant true
// uniquement lors de la toute première invocation.
func (c *Client) MarkUnregistered() bool {
	return c.unregistered.CompareAndSwap(false, true)
}

// EnqueueFrame soumet de manière non bloquante une trame immuable au client en appliquant la politique de contre-pression.
func (c *Client) EnqueueFrame(frame *Frame) bool {
	if c.closed.Load() {
		return false
	}

	select {
	case c.Send <- frame:
		return true
	default:
		// La file d'attente du client est pleine : application de la politique
		switch c.SlowPolicy {
		case SlowPolicyDropOldest:
			select {
			case <-c.Send: // Défausser l'ancienne trame
			default:
			}
			select {
			case c.Send <- frame:
				return true
			default:
				return false
			}

		case SlowPolicyDropNewest:
			// Défausser la nouvelle trame pour préserver l'historique en cours
			return false

		case SlowPolicyDisconnect:
			fallthrough
		default:
			if c.onSlow != nil {
				c.onSlow(c)
			}
			c.Close()
			return false
		}
	}
}

// Close clôture le client SSE et son canal d'émission.
func (c *Client) Close() {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		close(c.closeNotify)
	})
}

// Done retourne un canal notifié lors de la clôture du client.
func (c *Client) Done() <-chan struct{} {
	return c.closeNotify
}

// IsClosed indique si le client est déconnecté.
func (c *Client) IsClosed() bool {
	return c.closed.Load()
}
