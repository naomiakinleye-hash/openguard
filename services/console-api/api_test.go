package consoleapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	auditled "github.com/DiniMuhd7/openguard/services/audit-ledger"
)

const testJWTSecret = "test-secret-key"

// newTestServer creates a Server wired for tests (no real HTTP listener).
func newTestServer(t *testing.T) *Server {
	t.Helper()
	ledger := auditled.NewLedger(auditled.Config{}, zap.NewNop())
	events := NewEventStore()
	incidents := NewIncidentStore()
	return NewServer(Config{
		JWTSecret: testJWTSecret,
	}, ledger, events, incidents, zap.NewNop())
}

// validToken returns a signed JWT that passes authMiddleware.
func validToken(t *testing.T) string {
	t.Helper()
	claims := jwtv5.MapClaims{
		"sub": "admin",
		"exp": jwtv5.NewNumericDate(time.Now().Add(8 * time.Hour)),
	}
	token := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return signed
}

// expiredToken returns a signed JWT that is already expired.
func expiredToken(t *testing.T) string {
	t.Helper()
	claims := jwtv5.MapClaims{
		"sub": "admin",
		"exp": jwtv5.NewNumericDate(time.Now().Add(-1 * time.Hour)),
	}
	token := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return signed
}

func TestLogin_Success(t *testing.T) {
	s := newTestServer(t)
	body := `{"username":"admin","password":"changeme"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.handleLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp["token"] == "" {
		t.Error("expected non-empty token")
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	s := newTestServer(t)
	body := `{"username":"admin","password":"wrongpassword"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.handleLogin(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestLogin_MissingFields(t *testing.T) {
	s := newTestServer(t)
	body := `{}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.handleLogin(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestAuthMiddleware_NoToken(t *testing.T) {
	s := newTestServer(t)
	mux := http.NewServeMux()
	s.registerRoutes(mux)
	handler := s.authMiddleware(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	s := newTestServer(t)
	mux := http.NewServeMux()
	s.registerRoutes(mux)
	handler := s.authMiddleware(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
	req.Header.Set("Authorization", "Bearer this-is-not-a-jwt")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestAuthMiddleware_ExpiredToken(t *testing.T) {
	s := newTestServer(t)
	mux := http.NewServeMux()
	s.registerRoutes(mux)
	handler := s.authMiddleware(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
	req.Header.Set("Authorization", "Bearer "+expiredToken(t))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestHandleHealth(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	s.handleHealth(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("expected status=ok, got %q", resp["status"])
	}
}

func TestHandleEvents_Empty(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
	rr := httptest.NewRecorder()
	s.handleEvents(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	events, ok := resp["events"].([]interface{})
	if !ok {
		t.Fatalf("expected events array, got %T", resp["events"])
	}
	if len(events) != 0 {
		t.Errorf("expected empty events, got %d", len(events))
	}
	if resp["page"].(float64) != 1 {
		t.Errorf("expected page=1")
	}
	if resp["total"].(float64) != 0 {
		t.Errorf("expected total=0")
	}
}

func TestHandleEvents_WithData(t *testing.T) {
	s := newTestServer(t)
	s.events.Add(map[string]interface{}{"id": "evt-1", "type": "test"})
	s.events.Add(map[string]interface{}{"id": "evt-2", "type": "test"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
	rr := httptest.NewRecorder()
	s.handleEvents(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp["total"].(float64) != 2 {
		t.Errorf("expected total=2, got %v", resp["total"])
	}
}

func TestHandleIncidents_WithData(t *testing.T) {
	s := newTestServer(t)
	s.incidents.Add(&Incident{ID: "inc-1", Status: "pending"})
	s.incidents.Add(&Incident{ID: "inc-2", Status: "pending"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents", nil)
	rr := httptest.NewRecorder()
	s.handleIncidents(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp["total"].(float64) != 2 {
		t.Errorf("expected total=2, got %v", resp["total"])
	}
}

func TestHandleIncidentDetail_NotFound(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents/missing", nil)
	rr := httptest.NewRecorder()
	s.handleIncidentActions(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestHandleIncidentAction_Approve(t *testing.T) {
	s := newTestServer(t)
	s.incidents.Add(&Incident{ID: "inc-x", Status: "pending"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/inc-x/approve", nil)
	rr := httptest.NewRecorder()
	s.handleIncidentActions(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rr.Code, rr.Body.String())
	}
	// Status should be updated.
	inc, ok := s.incidents.Get("inc-x")
	if !ok {
		t.Fatal("expected to find inc-x")
	}
	if inc.Status != "approved" {
		t.Errorf("expected status=approved, got %s", inc.Status)
	}
}

func TestHandleIncidentAction_InvalidAction(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/x/nuke", nil)
	rr := httptest.NewRecorder()
	s.handleIncidentActions(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestCORSHeaders(t *testing.T) {
	s := newTestServer(t)
	mux := http.NewServeMux()
	s.registerRoutes(mux)
	handler := s.corsMiddleware(mux)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("expected Access-Control-Allow-Origin: *")
	}
	if rr.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("expected Access-Control-Allow-Methods to be set")
	}
	if rr.Header().Get("Access-Control-Allow-Headers") == "" {
		t.Error("expected Access-Control-Allow-Headers to be set")
	}
}

func TestCORSPreflight(t *testing.T) {
	s := newTestServer(t)
	mux := http.NewServeMux()
	s.registerRoutes(mux)
	handler := s.corsMiddleware(mux)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/events", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for OPTIONS preflight, got %d", rr.Code)
	}
}

func TestStatusCodeLogging(t *testing.T) {
	inner := &responseWriter{
		ResponseWriter: httptest.NewRecorder(),
		status:         http.StatusOK,
	}
	inner.WriteHeader(http.StatusNotFound)
	if inner.status != http.StatusNotFound {
		t.Errorf("expected captured status=404, got %d", inner.status)
	}
}
