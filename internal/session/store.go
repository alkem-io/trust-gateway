// Package session stores each in-progress signing journey and its OAuth state server-side.
package session

import (
	"errors"
	"sync"
	"time"
)

// Status is the client-facing signing status.
type Status string

const (
	// StatusPending means the request has not begun authorization yet.
	StatusPending Status = "pending"
	// StatusAuthorizing means the gateway is waiting for a browser callback.
	StatusAuthorizing Status = "authorizing"
	// StatusCompleted means a signed PDF is available.
	StatusCompleted Status = "completed"
	// StatusDeclined means the signer declined authorization.
	StatusDeclined Status = "declined"
	// StatusFailed means the signing journey failed.
	StatusFailed Status = "failed"
)

// Terminal reports whether a status is one of the three end states.
func (status Status) Terminal() bool {
	return status == StatusCompleted || status == StatusDeclined || status == StatusFailed
}

var (
	// ErrNotFound is returned for an unknown or expired lookup key.
	ErrNotFound = errors.New("session not found")
	// ErrTerminal is returned when a terminal session is resumed.
	ErrTerminal = errors.New("session already terminal")
	// ErrResuming is returned while another callback is advancing the session.
	ErrResuming = errors.New("session already resuming")
)

const evictGrace = 5 * time.Minute

// Session contains the server-side state for one signing journey.
type Session struct {
	CorrelationID string
	OAuthState    string
	ClientState   string
	Handle        []byte
	Status        Status
	Reason        string
	Conformance   string
	ResultPDF     []byte
	Evidence      []byte
	CreatedAt     time.Time
	ExpiresAt     time.Time
	resuming      bool
}

// Terminal reports whether the session has reached an end state.
func (session *Session) Terminal() bool {
	return session.Status.Terminal()
}

// View is a race-free snapshot of fields consumed by the HTTP layer.
type View struct {
	CorrelationID string
	ClientState   string
	Status        Status
	Reason        string
	ResultPDF     []byte
	Evidence      []byte
}

// Memory is the single-replica in-memory session store used by the pilot.
type Memory struct {
	mu      sync.Mutex
	byID    map[string]*Session
	byState map[string]string
	clock   func() time.Time
}

// NewMemory returns an empty session store.
func NewMemory() *Memory {
	return &Memory{
		byID:    make(map[string]*Session),
		byState: make(map[string]string),
		clock:   time.Now,
	}
}

// New atomically creates the complete session envelope and indexes its initial OAuth state.
func (memory *Memory) New(correlationID, oauthState, clientState, conformance string, ttl time.Duration) *Session {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	memory.evictExpiredLocked()
	now := memory.clock()
	session := &Session{
		CorrelationID: correlationID,
		OAuthState:    oauthState,
		ClientState:   clientState,
		Status:        StatusAuthorizing,
		Conformance:   conformance,
		CreatedAt:     now,
		ExpiresAt:     now.Add(ttl),
	}
	memory.byID[correlationID] = session
	if oauthState != "" {
		memory.byState[oauthState] = correlationID
	}
	return session
}

// Get returns a session by correlation ID, applying TTL expiry first.
func (memory *Memory) Get(correlationID string) (*Session, error) {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	session := memory.byID[correlationID]
	if session == nil {
		return nil, ErrNotFound
	}
	memory.expireLocked(session)
	return session, nil
}

// GetByState returns the session for a currently pending OAuth state.
func (memory *Memory) GetByState(oauthState string) (*Session, error) {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	correlationID := memory.byState[oauthState]
	if correlationID == "" {
		return nil, ErrNotFound
	}
	session := memory.byID[correlationID]
	if session == nil {
		return nil, ErrNotFound
	}
	memory.expireLocked(session)
	if memory.byState[oauthState] != correlationID {
		return nil, ErrNotFound
	}
	return session, nil
}

// ViewByID returns a synchronized snapshot by correlation ID.
func (memory *Memory) ViewByID(correlationID string) (View, error) {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	session := memory.byID[correlationID]
	if session == nil {
		return View{}, ErrNotFound
	}
	memory.expireLocked(session)
	return View{
		CorrelationID: session.CorrelationID,
		ClientState:   session.ClientState,
		Status:        session.Status,
		Reason:        session.Reason,
		ResultPDF:     session.ResultPDF,
		Evidence:      session.Evidence,
	}, nil
}

// ConsumeForResume atomically claims a non-terminal session and consumes its pending state.
func (memory *Memory) ConsumeForResume(session *Session) ([]byte, error) {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	memory.expireLocked(session)
	if session.Terminal() {
		return nil, ErrTerminal
	}
	if session.resuming {
		return nil, ErrResuming
	}
	session.resuming = true
	if session.OAuthState != "" {
		delete(memory.byState, session.OAuthState)
		session.OAuthState = ""
	}
	return append([]byte(nil), session.Handle...), nil
}

// Update serializes a mutation with concurrent views.
func (memory *Memory) Update(_ *Session, mutate func()) {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	mutate()
}

// SetState indexes the next OAuth state and releases the in-flight resume claim.
func (memory *Memory) SetState(session *Session, oauthState string) {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	if session.OAuthState != "" {
		delete(memory.byState, session.OAuthState)
	}
	session.OAuthState = oauthState
	if oauthState != "" {
		memory.byState[oauthState] = session.CorrelationID
	}
	session.resuming = false
}

// Finalize removes resumable secrets while retaining the result until eviction.
func (memory *Memory) Finalize(session *Session) {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	if session.OAuthState != "" {
		delete(memory.byState, session.OAuthState)
		session.OAuthState = ""
	}
	session.Handle = nil
	session.resuming = false
}

func (memory *Memory) expireLocked(session *Session) {
	if session.Terminal() || !memory.clock().After(session.ExpiresAt) {
		return
	}
	session.Status = StatusFailed
	session.Reason = "session_expired"
	session.Handle = nil
	if session.OAuthState != "" {
		delete(memory.byState, session.OAuthState)
		session.OAuthState = ""
	}
}

func (memory *Memory) evictExpiredLocked() {
	now := memory.clock()
	for correlationID, session := range memory.byID {
		if !session.resuming && now.After(session.ExpiresAt.Add(evictGrace)) {
			if session.OAuthState != "" {
				delete(memory.byState, session.OAuthState)
			}
			delete(memory.byID, correlationID)
		}
	}
}
