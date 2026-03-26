// Package consoleapi — users.go provides RBAC user account management.
// Roles (ascending privilege): viewer < analyst < operator < admin.
package consoleapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// UserRole defines the access level for a console user.
type UserRole string

const (
	// RoleViewer allows read-only access (events, incidents, audit log).
	RoleViewer UserRole = "viewer"
	// RoleAnalyst extends viewer with approve/deny on T2 incidents.
	RoleAnalyst UserRole = "analyst"
	// RoleOperator extends analyst with configuration management.
	RoleOperator UserRole = "operator"
	// RoleAdmin has full access including user management.
	RoleAdmin UserRole = "admin"
)

// contextKeyRole stores the authenticated user's role from the JWT.
const contextKeyRole contextKey = "role"

// userRecord represents a console user.
type userRecord struct {
	Username     string   `json:"username"`
	PasswordHash []byte   `json:"-"`
	Role         UserRole `json:"role"`
	CreatedAt    string   `json:"created_at"`
}

// roleOrder maps roles to their privilege level for comparison.
var roleOrder = map[UserRole]int{
	RoleViewer: 0, RoleAnalyst: 1, RoleOperator: 2, RoleAdmin: 3,
}

// hasRole returns true when actual meets or exceeds minimum.
func hasRole(actual, minimum UserRole) bool {
	return roleOrder[actual] >= roleOrder[minimum]
}

// requireRole wraps a handler and rejects requests from users below minRole.
func (s *Server) requireRole(minRole UserRole, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		role, _ := r.Context().Value(contextKeyRole).(UserRole)
		if !hasRole(role, minRole) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "insufficient privileges"})
			return
		}
		next(w, r)
	}
}

// handleUsers dispatches user management CRUD (admin only).
//
// Routes:
//
//	GET    /api/v1/users            – list all users
//	POST   /api/v1/users            – create a user
//	PUT    /api/v1/users/{username} – update role or password
//	DELETE /api/v1/users/{username} – delete a user
func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	role, _ := r.Context().Value(contextKeyRole).(UserRole)
	if role != RoleAdmin {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin role required"})
		return
	}

	suffix := strings.TrimPrefix(r.URL.Path, "/api/v1/users")
	suffix = strings.TrimPrefix(suffix, "/")

	switch {
	case r.Method == http.MethodGet && suffix == "":
		s.listUsers(w, r)
	case r.Method == http.MethodPost && suffix == "":
		s.createUser(w, r)
	case r.Method == http.MethodPut && suffix != "":
		s.updateUser(w, r, suffix)
	case r.Method == http.MethodDelete && suffix != "":
		s.deleteUser(w, r, suffix)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) listUsers(w http.ResponseWriter, _ *http.Request) {
	s.usersMu.RLock()
	defer s.usersMu.RUnlock()
	out := make([]map[string]interface{}, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, map[string]interface{}{
			"username":   u.Username,
			"role":       u.Role,
			"created_at": u.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"users": out})
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string   `json:"username"`
		Password string   `json:"password"`
		Role     UserRole `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username and password required"})
		return
	}
	if _, ok := roleOrder[req.Role]; !ok || req.Role == "" {
		req.Role = RoleViewer
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Error("users: bcrypt failed", zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	s.usersMu.Lock()
	defer s.usersMu.Unlock()
	if _, exists := s.users[req.Username]; exists {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "username already exists"})
		return
	}
	newRecord := &userRecord{
		Username:     req.Username,
		PasswordHash: hash,
		Role:         req.Role,
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	s.users[req.Username] = newRecord
	go sqliteUpsertUser(s.db, newRecord)
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"username": req.Username,
		"role":     req.Role,
	})
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request, username string) {
	var req struct {
		Role     UserRole `json:"role"`
		Password string   `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	s.usersMu.Lock()
	defer s.usersMu.Unlock()
	u, exists := s.users[username]
	if !exists {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}
	// Prevent demoting the last admin.
	if req.Role != "" && req.Role != RoleAdmin && u.Role == RoleAdmin {
		if s.countRoleLocked(RoleAdmin) <= 1 {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "cannot demote the last admin"})
			return
		}
	}
	if req.Role != "" {
		if _, ok := roleOrder[req.Role]; ok {
			u.Role = req.Role
		}
	}
	if req.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			s.logger.Error("users: bcrypt failed", zap.Error(err))
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		u.PasswordHash = hash
	}
	go sqliteUpsertUser(s.db, u)
	writeJSON(w, http.StatusOK, map[string]interface{}{"username": u.Username, "role": u.Role})
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request, username string) {
	actor, _ := r.Context().Value(contextKeyActor).(string)
	if actor == username {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "cannot delete your own account"})
		return
	}
	s.usersMu.Lock()
	defer s.usersMu.Unlock()
	u, exists := s.users[username]
	if !exists {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}
	if u.Role == RoleAdmin && s.countRoleLocked(RoleAdmin) <= 1 {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "cannot delete the last admin"})
		return
	}
	delete(s.users, username)
	go sqliteDeleteUser(s.db, username)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "username": username})
}

// countRoleLocked counts users with the given role. Caller must hold usersMu (at least read lock).
func (s *Server) countRoleLocked(role UserRole) int {
	n := 0
	for _, u := range s.users {
		if u.Role == role {
			n++
		}
	}
	return n
}
