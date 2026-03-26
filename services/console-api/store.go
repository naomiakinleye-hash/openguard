// Package consoleapi — store.go provides thread-safe in-memory stores for
// security events and incidents, used by the console API handlers.
package consoleapi

import (
	"database/sql"
	"fmt"
	"sync"
	"time"
)

// Incident holds the data for a pending or resolved incident.
type Incident struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type,omitempty"`
	Tier        int                    `json:"tier,omitempty"`
	RiskScore   float64                `json:"risk_score,omitempty"`
	Status      string                 `json:"status"`
	CreatedAt   string                 `json:"created_at"`
	Description string                 `json:"description,omitempty"`
	EventID     string                 `json:"event_id,omitempty"`
	Extra       map[string]interface{} `json:"-"`
	// Explainability fields (populated by the orchestrator).
	MatchedRules    []string `json:"matched_rules,omitempty"`
	PolicyCitations []string `json:"policy_citations,omitempty"`
	Confidence      float64  `json:"confidence,omitempty"`
	Explanation     string   `json:"explanation,omitempty"`
	BlastRadius     string   `json:"blast_radius,omitempty"`
}

// EventStore is an append-only, paginated in-memory store for security events.
type EventStore struct {
	mu      sync.RWMutex
	events  []map[string]interface{}
	byID    map[string]map[string]interface{}
	subs    []chan map[string]interface{}
	counter int
	db      *sql.DB // optional SQLite backend; nil = in-memory only
}

// NewEventStore constructs a new EventStore. An optional *sql.DB enables
// SQLite persistence; pass nothing or nil for in-memory-only mode.
func NewEventStore(db ...*sql.DB) *EventStore {
	var d *sql.DB
	if len(db) > 0 {
		d = db[0]
	}
	return &EventStore{
		byID: make(map[string]map[string]interface{}),
		db:   d,
	}
}

// Subscribe returns a buffered channel that receives a copy of each event as it
// is added to the store. Call Unsubscribe to clean up the channel.
func (s *EventStore) Subscribe() chan map[string]interface{} {
	ch := make(chan map[string]interface{}, 64)
	s.mu.Lock()
	s.subs = append(s.subs, ch)
	s.mu.Unlock()
	return ch
}

// Unsubscribe removes and closes a previously subscribed channel.
func (s *EventStore) Unsubscribe(ch chan map[string]interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, sub := range s.subs {
		if sub == ch {
			s.subs = append(s.subs[:i], s.subs[i+1:]...)
			close(ch)
			return
		}
	}
}

// Add appends an event to the store. If the event has no "id" field, one is
// assigned automatically. Subscribers are notified asynchronously.
func (s *EventStore) Add(event map[string]interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counter++
	id, _ := event["id"].(string)
	if id == "" {
		id, _ = event["event_id"].(string)
	}
	if id == "" {
		id = fmt.Sprintf("evt-%d-%d", time.Now().UnixNano(), s.counter)
		event["id"] = id
	}
	s.events = append(s.events, event)
	s.byID[id] = event
	// Persist to SQLite if configured (best-effort, non-blocking).
	if s.db != nil {
		go sqlitePersistEvent(s.db, event)
	}
	// Notify subscribers — non-blocking so slow readers don't stall ingest.
	for _, ch := range s.subs {
		select {
		case ch <- event:
		default:
		}
	}
}

// List returns a paginated slice of events and the total count.
// page is 1-based; pageSize must be > 0.
func (s *EventStore) List(page, pageSize int) (items []map[string]interface{}, total int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	total = len(s.events)
	if pageSize <= 0 || page <= 0 {
		return nil, total
	}
	start := (page - 1) * pageSize
	if start >= total {
		return []map[string]interface{}{}, total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	items = make([]map[string]interface{}, end-start)
	copy(items, s.events[start:end])
	return items, total
}

// Get returns the event with the given id, or false if not found.
func (s *EventStore) Get(id string) (map[string]interface{}, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.byID[id]
	return e, ok
}

// IncidentStore is an append-only, paginated in-memory store for incidents.
type IncidentStore struct {
	mu        sync.RWMutex
	incidents []*Incident
	byID      map[string]*Incident
	counter   int
	db        *sql.DB // optional SQLite backend
}

// NewIncidentStore constructs a new IncidentStore. An optional *sql.DB enables
// SQLite persistence.
func NewIncidentStore(db ...*sql.DB) *IncidentStore {
	var d *sql.DB
	if len(db) > 0 {
		d = db[0]
	}
	return &IncidentStore{
		byID: make(map[string]*Incident),
		db:   d,
	}
}

// Add appends an incident to the store. If the incident has no ID, one is
// assigned automatically.
func (s *IncidentStore) Add(incident *Incident) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counter++
	if incident.ID == "" {
		incident.ID = fmt.Sprintf("inc-%d-%d", time.Now().UnixNano(), s.counter)
	}
	if incident.CreatedAt == "" {
		incident.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	s.incidents = append(s.incidents, incident)
	s.byID[incident.ID] = incident
	// Persist to SQLite if configured.
	if s.db != nil {
		go sqlitePersistIncident(s.db, incident)
	}
}

// List returns a paginated slice of incidents and the total count.
// page is 1-based; pageSize must be > 0.
func (s *IncidentStore) List(page, pageSize int) (items []*Incident, total int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	total = len(s.incidents)
	if pageSize <= 0 || page <= 0 {
		return nil, total
	}
	start := (page - 1) * pageSize
	if start >= total {
		return []*Incident{}, total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	items = make([]*Incident, end-start)
	copy(items, s.incidents[start:end])
	return items, total
}

// Get returns the incident with the given id, or false if not found.
func (s *IncidentStore) Get(id string) (*Incident, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	inc, ok := s.byID[id]
	return inc, ok
}

// UpdateStatus updates the status of an incident by ID.
// Returns true if the incident was found and updated.
func (s *IncidentStore) UpdateStatus(id, status string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	inc, ok := s.byID[id]
	if !ok {
		return false
	}
	inc.Status = status
	// Sync status to SQLite.
	if s.db != nil {
		go sqliteUpdateIncidentStatus(s.db, id, status)
	}
	return true
}
