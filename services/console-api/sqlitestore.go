// Package consoleapi — sqlitestore.go provides optional SQLite persistence for
// EventStore and IncidentStore so data survives process restarts.
package consoleapi

import (
	"context"
	"database/sql"
	"encoding/json"

	"go.uber.org/zap"
	_ "modernc.org/sqlite" // pure-Go SQLite driver; no CGO required
)

// OpenSQLite opens (or creates) a SQLite database at dbPath, creates the
// required tables, and returns the *sql.DB.  Pass an empty string or ":memory:"
// for a transient in-process database.
func OpenSQLite(dbPath string, logger *zap.Logger) (*sql.DB, error) {
	if dbPath == "" {
		dbPath = ":memory:"
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	// SQLite allows only one writer at a time; cap to 1 open connection
	// to avoid "database is locked" errors.
	db.SetMaxOpenConns(1)
	if err := sqliteCreateSchema(db); err != nil {
		db.Close() //nolint:errcheck
		return nil, err
	}
	logger.Info("sqlite: opened database", zap.String("path", dbPath))
	return db, nil
}

func sqliteCreateSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS events (
			id      TEXT PRIMARY KEY,
			payload TEXT NOT NULL,
			ts      INTEGER NOT NULL DEFAULT (strftime('%s','now'))
		);
		CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);

		CREATE TABLE IF NOT EXISTS incidents (
			id         TEXT PRIMARY KEY,
			payload    TEXT NOT NULL,
			status     TEXT NOT NULL,
			created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
		);
		CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at);

		CREATE TABLE IF NOT EXISTS users (
			username      TEXT PRIMARY KEY,
			password_hash TEXT NOT NULL,
			role          TEXT NOT NULL,
			created_at    TEXT NOT NULL
		);
	`)
	return err
}

// sqliteUpsertUser writes (or replaces) a user record in SQLite.
// Errors are swallowed — persistence is best-effort.
func sqliteUpsertUser(db *sql.DB, u *userRecord) {
	if db == nil {
		return
	}
	db.ExecContext(context.Background(), //nolint:errcheck
		`INSERT OR REPLACE INTO users(username, password_hash, role, created_at) VALUES(?,?,?,?)`,
		u.Username, string(u.PasswordHash), string(u.Role), u.CreatedAt,
	)
}

// sqliteDeleteUser removes a user from SQLite.
func sqliteDeleteUser(db *sql.DB, username string) {
	if db == nil {
		return
	}
	db.ExecContext(context.Background(), //nolint:errcheck
		`DELETE FROM users WHERE username=?`, username,
	)
}

// LoadUsersFromSQLite reads all persisted user records from SQLite.
func LoadUsersFromSQLite(db *sql.DB) ([]*userRecord, error) {
	rows, err := db.QueryContext(context.Background(),
		`SELECT username, password_hash, role, created_at FROM users`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var users []*userRecord
	for rows.Next() {
		var u userRecord
		var hash, role string
		if err := rows.Scan(&u.Username, &hash, &role, &u.CreatedAt); err != nil {
			continue
		}
		u.PasswordHash = []byte(hash)
		u.Role = UserRole(role)
		users = append(users, &u)
	}
	return users, rows.Err()
}

// sqlitePersistEvent writes an event to SQLite as JSON.
// Errors are intentionally swallowed — persistence is best-effort.
func sqlitePersistEvent(db *sql.DB, event map[string]interface{}) {
	if db == nil {
		return
	}
	id, _ := event["id"].(string)
	if id == "" {
		id, _ = event["event_id"].(string)
	}
	payload, _ := json.Marshal(event)
	db.ExecContext(context.Background(), //nolint:errcheck
		`INSERT OR REPLACE INTO events(id, payload) VALUES(?,?)`,
		id, string(payload),
	)
}

// sqlitePersistIncident writes an incident to SQLite.
func sqlitePersistIncident(db *sql.DB, inc *Incident) {
	if db == nil {
		return
	}
	payload, _ := json.Marshal(inc)
	db.ExecContext(context.Background(), //nolint:errcheck
		`INSERT OR REPLACE INTO incidents(id, payload, status) VALUES(?,?,?)`,
		inc.ID, string(payload), inc.Status,
	)
}

// sqliteUpdateIncidentStatus updates the status field in SQLite.
func sqliteUpdateIncidentStatus(db *sql.DB, id, status string) {
	if db == nil {
		return
	}
	db.ExecContext(context.Background(), //nolint:errcheck
		`UPDATE incidents SET status=? WHERE id=?`, status, id,
	)
}

// LoadEventsFromSQLite reads all persisted events into the EventStore.
// Call once after opening the DB, before starting the server.
func (s *EventStore) LoadEventsFromSQLite(db *sql.DB) error {
	rows, err := db.QueryContext(context.Background(),
		`SELECT payload FROM events ORDER BY ts ASC`)
	if err != nil {
		return err
	}
	defer rows.Close() //nolint:errcheck
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		var event map[string]interface{}
		if json.Unmarshal([]byte(raw), &event) != nil {
			continue
		}
		s.mu.Lock()
		id, _ := event["id"].(string)
		s.events = append(s.events, event)
		if id != "" {
			s.byID[id] = event
		}
		s.counter++
		s.mu.Unlock()
	}
	return rows.Err()
}

// LoadIncidentsFromSQLite reads all persisted incidents into the IncidentStore.
func (s *IncidentStore) LoadIncidentsFromSQLite(db *sql.DB) error {
	rows, err := db.QueryContext(context.Background(),
		`SELECT payload FROM incidents ORDER BY created_at ASC`)
	if err != nil {
		return err
	}
	defer rows.Close() //nolint:errcheck
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		var inc Incident
		if json.Unmarshal([]byte(raw), &inc) != nil {
			continue
		}
		s.mu.Lock()
		s.incidents = append(s.incidents, &inc)
		s.byID[inc.ID] = &inc
		s.counter++
		s.mu.Unlock()
	}
	return rows.Err()
}
