// oauth.go — Per-user OAuth2 sign-in and credential management for AI model providers.
//
// Providers that support OAuth2 (currently Google Gemini) use the standard
// authorization-code flow:
//
//  1. Frontend calls GET /api/v1/models/oauth/start?provider=google-gemini
//     (authenticated with the user's OpenGuard JWT).
//  2. Backend returns {"auth_url": "https://accounts.google.com/..."}.
//  3. Frontend opens a popup to that URL.
//  4. Google redirects the popup to /api/v1/models/oauth/callback.
//  5. Backend exchanges the code for tokens, stores them per-user, and
//     renders an HTML page that postMessages the result back to the opener.
//
// Providers without OAuth2 (OpenAI, Anthropic) use a credential-save endpoint:
//
//  POST  /api/v1/models/credentials   {"provider":"openai-codex","credential":"sk-..."}
//  DELETE /api/v1/models/credentials  ?provider=openai-codex
//
// Credentials are stored in memory on the Server and are scoped to the
// authenticated OpenGuard user (identified by the JWT "sub" claim).
package consoleapi

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
)

// ── Types ─────────────────────────────────────────────────────────────────────

// providerCredential stores OAuth2 tokens or user-supplied credentials for one
// (user, provider) pair.
type providerCredential struct {
	Provider     string    `json:"provider"`
	AccessToken  string    `json:"access_token"`  // OAuth2 access token or user API key
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	ConnectedAt  time.Time `json:"connected_at"`
}

// oauthState is kept server-side during an in-flight OAuth2 authorization flow
// so the callback can map a returned state value back to the originating user.
type oauthState struct {
	Username string
	Provider string
	Expiry   time.Time
}

// oauthProviderConfig holds the OAuth2 endpoints and scopes for a provider.
type oauthProviderConfig struct {
	AuthURL         string
	TokenURL        string
	Scopes          []string
	ClientIDEnv     string
	ClientSecretEnv string
}

// oauthProviderConfigs maps provider ID to its OAuth2 configuration.
// Only providers with a real OAuth2 authorization server are listed here.
// Unused providers use the credential-save endpoint instead.
var oauthProviderConfigs = map[string]oauthProviderConfig{
	"google-gemini": {
		AuthURL:         "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:        "https://oauth2.googleapis.com/token",
		Scopes:          []string{"https://www.googleapis.com/auth/generative-language"},
		ClientIDEnv:     "GOOGLE_CLIENT_ID",
		ClientSecretEnv: "GOOGLE_CLIENT_SECRET",
	},
}

// hasOAuth reports whether the given provider supports OAuth2 sign-in.
func hasOAuth(provider string) bool {
	_, ok := oauthProviderConfigs[provider]
	return ok
}

// ── Per-user credential storage ───────────────────────────────────────────────

// credKey builds the sync.Map key for a (username, provider) pair.
// Uses a NUL separator that cannot appear in either field.
func credKey(username, provider string) string { return username + "\x00" + provider }

// setUserCred stores a credential for a (username, provider) pair.
func (s *Server) setUserCred(username, provider string, cred *providerCredential) {
	s.userCreds.Store(credKey(username, provider), cred)
}

// getUserCred retrieves the stored credential for a (username, provider) pair.
func (s *Server) getUserCred(username, provider string) (*providerCredential, bool) {
	v, ok := s.userCreds.Load(credKey(username, provider))
	if !ok {
		return nil, false
	}
	cred, ok := v.(*providerCredential)
	return cred, ok
}

// deleteUserCred removes the stored credential for a (username, provider) pair.
func (s *Server) deleteUserCred(username, provider string) {
	s.userCreds.Delete(credKey(username, provider))
}

// isUserConnected reports whether the given user has a live credential for the
// provider (refreshing an expired OAuth2 access token if a refresh token is available).
func (s *Server) isUserConnected(username, provider string) bool {
	cred, ok := s.getUserCred(username, provider)
	if !ok || cred.AccessToken == "" {
		return false
	}
	// For OAuth2 tokens refresh 1 minute before actual expiry.
	if !cred.ExpiresAt.IsZero() && time.Now().Add(time.Minute).After(cred.ExpiresAt) {
		if cred.RefreshToken == "" {
			return false
		}
		if err := s.refreshOAuthToken(username, provider, cred); err != nil {
			s.logger.Warn("oauth2 background refresh failed",
				zap.String("provider", provider), zap.Error(err))
			return false
		}
	}
	return true
}

// getAccessToken returns a valid access token for a (username, provider) pair,
// refreshing an expired OAuth2 token when a refresh token is available.
func (s *Server) getAccessToken(username, provider string) (string, error) {
	cred, ok := s.getUserCred(username, provider)
	if !ok || cred.AccessToken == "" {
		return "", fmt.Errorf("%s: not connected — sign in via Model Settings", provider)
	}
	if !cred.ExpiresAt.IsZero() && time.Now().Add(time.Minute).After(cred.ExpiresAt) {
		if cred.RefreshToken == "" {
			return "", fmt.Errorf("%s token expired — please reconnect in Model Settings", provider)
		}
		if err := s.refreshOAuthToken(username, provider, cred); err != nil {
			return "", fmt.Errorf("refresh %s token: %w", provider, err)
		}
		cred, ok = s.getUserCred(username, provider)
		if !ok {
			return "", fmt.Errorf("credential unavailable after refresh")
		}
	}
	return cred.AccessToken, nil
}

// refreshOAuthToken exchanges a refresh token for a new access token and updates
// the stored credential.
func (s *Server) refreshOAuthToken(username, provider string, cred *providerCredential) error {
	cfg, ok := oauthProviderConfigs[provider]
	if !ok {
		return fmt.Errorf("no OAuth2 config for %s", provider)
	}
	params := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {cred.RefreshToken},
		"client_id":     {os.Getenv(cfg.ClientIDEnv)},
		"client_secret": {os.Getenv(cfg.ClientSecretEnv)},
	}
	resp, err := http.PostForm(cfg.TokenURL, params) //nolint:noctx
	if err != nil {
		return fmt.Errorf("token refresh request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token refresh status %d: %s", resp.StatusCode, string(body))
	}
	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return fmt.Errorf("decode token refresh: %w", err)
	}
	updated := &providerCredential{
		Provider:     cred.Provider,
		AccessToken:  tok.AccessToken,
		RefreshToken: cred.RefreshToken,
		ConnectedAt:  cred.ConnectedAt,
	}
	if tok.RefreshToken != "" {
		updated.RefreshToken = tok.RefreshToken
	}
	if tok.ExpiresIn > 0 {
		updated.ExpiresAt = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	}
	s.setUserCred(username, provider, updated)
	return nil
}

// ── OAuth2 flow ───────────────────────────────────────────────────────────────

// generateOAuthState creates a cryptographically random state string for CSRF protection.
func generateOAuthState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// oauthRedirectURI builds the absolute callback URL from the incoming request.
func oauthRedirectURI(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s/api/v1/models/oauth/callback", scheme, r.Host)
}

// handleOAuthStart handles GET /api/v1/models/oauth/start?provider=X.
// Returns {"auth_url":"..."} so the frontend can open a popup to the provider's sign-in page.
// The request must be authenticated with a valid OpenGuard JWT.
func (s *Server) handleOAuthStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	provider := r.URL.Query().Get("provider")
	cfg, ok := oauthProviderConfigs[provider]
	if !ok {
		writeJSON(w, http.StatusBadRequest,
			map[string]string{"error": "provider does not support OAuth2 sign-in"})
		return
	}
	clientID := os.Getenv(cfg.ClientIDEnv)
	if clientID == "" {
		writeJSON(w, http.StatusServiceUnavailable,
			map[string]string{"error": cfg.ClientIDEnv + " is not configured on this server"})
		return
	}
	username, _ := r.Context().Value(contextKeyActor).(string)
	state, err := generateOAuthState()
	if err != nil {
		http.Error(w, "state generation failed", http.StatusInternalServerError)
		return
	}
	// Store state → (username, provider) for the callback to retrieve.
	// States expire after 10 minutes; expired-but-unclaimed states are
	// naturally small in number and cleaned up at callback time.
	s.oauthStates.Store(state, &oauthState{
		Username: username,
		Provider: provider,
		Expiry:   time.Now().Add(10 * time.Minute),
	})
	params := url.Values{
		"client_id":     {clientID},
		"redirect_uri":  {oauthRedirectURI(r)},
		"response_type": {"code"},
		"scope":         {strings.Join(cfg.Scopes, " ")},
		"state":         {state},
		"access_type":   {"offline"},
		"prompt":        {"consent"}, // always return refresh_token
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"auth_url": cfg.AuthURL + "?" + params.Encode(),
	})
}

// handleOAuthCallback handles GET /api/v1/models/oauth/callback?code=...&state=...
// This is called by the OAuth2 provider as a browser redirect, NOT by the authenticated
// user's fetch — so it is exempt from JWT auth middleware (added in authMiddleware allowlist).
func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if state == "" {
		s.writeOAuthCallbackPage(w, false, "", "missing state parameter")
		return
	}
	v, ok := s.oauthStates.LoadAndDelete(state)
	if !ok {
		s.writeOAuthCallbackPage(w, false, "", "invalid or expired state — please try again")
		return
	}
	oas := v.(*oauthState)
	if time.Now().After(oas.Expiry) {
		s.writeOAuthCallbackPage(w, false, oas.Provider, "sign-in timed out — please try again")
		return
	}
	// Provider may return an error (e.g. user denied access).
	if errCode := r.URL.Query().Get("error"); errCode != "" {
		desc := r.URL.Query().Get("error_description")
		if desc == "" {
			desc = errCode
		}
		s.writeOAuthCallbackPage(w, false, oas.Provider, desc)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		s.writeOAuthCallbackPage(w, false, oas.Provider, "no authorization code returned")
		return
	}
	cred, err := s.exchangeOAuthCode(r, oas.Provider, code)
	if err != nil {
		s.logger.Warn("oauth2 code exchange failed",
			zap.String("provider", oas.Provider),
			zap.String("user", oas.Username),
			zap.Error(err))
		s.writeOAuthCallbackPage(w, false, oas.Provider, err.Error())
		return
	}
	cred.Provider = oas.Provider
	cred.ConnectedAt = time.Now()
	s.setUserCred(oas.Username, oas.Provider, cred)
	s.logger.Info("oauth2 sign-in complete",
		zap.String("provider", oas.Provider),
		zap.String("user", oas.Username))
	s.writeOAuthCallbackPage(w, true, oas.Provider, "")
}

// exchangeOAuthCode exchanges an authorization code for access/refresh tokens.
func (s *Server) exchangeOAuthCode(r *http.Request, provider, code string) (*providerCredential, error) {
	cfg := oauthProviderConfigs[provider]
	params := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {os.Getenv(cfg.ClientIDEnv)},
		"client_secret": {os.Getenv(cfg.ClientSecretEnv)},
		"redirect_uri":  {oauthRedirectURI(r)},
	}
	resp, err := http.PostForm(cfg.TokenURL, params) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("token exchange request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange status %d: %s", resp.StatusCode, string(body))
	}
	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	if tok.AccessToken == "" {
		return nil, fmt.Errorf("no access_token in response")
	}
	cred := &providerCredential{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
	}
	if tok.ExpiresIn > 0 {
		cred.ExpiresAt = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	}
	return cred, nil
}

// ── Callback HTML page ────────────────────────────────────────────────────────

type callbackPageData struct {
	Success    bool
	Provider   string
	ErrorMsg   string
	SuccessJS  template.JS
	ProviderJS template.JS
	ErrorJS    template.JS
	HasError   bool
}

var oauthCallbackTmpl = template.Must(template.New("oauth-callback").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>OpenGuard — {{if .Success}}Connected{{else}}Error{{end}}</title>
  <style>
    body { font-family: sans-serif; text-align: center; padding: 3rem;
           background: #0f172a; color: #f1f5f9; }
    .icon { font-size: 2.5rem; margin-bottom: 1rem; }
    p { color: #cbd5e1; }
    strong { color: #f1f5f9; }
    small { color: #475569; font-size: 0.85rem; }
  </style>
</head>
<body>
  <div class="icon">{{if .Success}}✅{{else}}❌{{end}}</div>
  {{if .Success}}
    <p>Successfully signed in to <strong>{{.Provider}}</strong>.</p>
  {{else}}
    <p>Sign-in failed: {{.ErrorMsg}}</p>
  {{end}}
  <p><small>You may close this window.</small></p>
  <script>
  (function() {
    var msg = { type: "og-oauth-result", success: {{.SuccessJS}}, provider: {{.ProviderJS}}{{if .HasError}}, error: {{.ErrorJS}}{{end}} };
    if (window.opener) {
      window.opener.postMessage(msg, window.location.origin);
      setTimeout(function() { window.close(); }, 700);
    }
  })();
  </script>
</body>
</html>`))

// writeOAuthCallbackPage renders the popup result page.
func (s *Server) writeOAuthCallbackPage(w http.ResponseWriter, success bool, provider, errMsg string) {
	pJS, _ := json.Marshal(provider)
	eJS, _ := json.Marshal(errMsg)
	successJS := template.JS("false")
	if success {
		successJS = template.JS("true")
	}
	data := callbackPageData{
		Success:    success,
		Provider:   provider,
		ErrorMsg:   errMsg,
		SuccessJS:  successJS,
		ProviderJS: template.JS(pJS),
		ErrorJS:    template.JS(eJS),
		HasError:   !success,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := oauthCallbackTmpl.Execute(w, data); err != nil {
		s.logger.Error("oauth callback page render failed", zap.Error(err))
	}
}

// ── Credential management endpoints ──────────────────────────────────────────

// handleCredentials dispatches POST and DELETE to the appropriate sub-handler.
func (s *Server) handleCredentials(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.handleCredentialSave(w, r)
	case http.MethodDelete:
		s.handleCredentialDelete(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleCredentialSave handles POST /api/v1/models/credentials.
// For providers that do not support OAuth2 (OpenAI, Anthropic), the user
// supplies their API key which is stored server-side per user account.
func (s *Server) handleCredentialSave(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 8*1024))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	var req struct {
		Provider   string `json:"provider"`
		Credential string `json:"credential"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.Provider == "" || req.Credential == "" {
		writeJSON(w, http.StatusBadRequest,
			map[string]string{"error": "provider and credential are required"})
		return
	}
	if !isValidProvider(req.Provider) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown provider"})
		return
	}
	if hasOAuth(req.Provider) {
		writeJSON(w, http.StatusBadRequest,
			map[string]string{"error": "use the OAuth2 sign-in flow for this provider"})
		return
	}
	username, _ := r.Context().Value(contextKeyActor).(string)
	s.setUserCred(username, req.Provider, &providerCredential{
		Provider:    req.Provider,
		AccessToken: req.Credential, // API key stored as the access token field
		ConnectedAt: time.Now(),
	})
	s.logger.Info("credential saved",
		zap.String("provider", req.Provider), zap.String("user", username))
	writeJSON(w, http.StatusOK, map[string]string{"status": "connected", "provider": req.Provider})
}

// handleCredentialDelete handles DELETE /api/v1/models/credentials?provider=X.
func (s *Server) handleCredentialDelete(w http.ResponseWriter, r *http.Request) {
	provider := r.URL.Query().Get("provider")
	if !isValidProvider(provider) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown provider"})
		return
	}
	username, _ := r.Context().Value(contextKeyActor).(string)
	s.deleteUserCred(username, provider)
	s.logger.Info("credential removed",
		zap.String("provider", provider), zap.String("user", username))
	writeJSON(w, http.StatusOK, map[string]string{"status": "disconnected", "provider": provider})
}
