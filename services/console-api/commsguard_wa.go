// Package consoleapi — commsguard_wa.go implements the WhatsApp multi-device
// (WA Web) live session for CommsGuard.
//
// Instead of relying on the WhatsApp Cloud API webhooks, this module connects
// as a companion device using the WhatsApp multi-device protocol (the same
// protocol WhatsApp Web, WhatsApp Desktop, etc. use). Pairing is performed
// by scanning a QR code with the primary phone. Once paired the session
// persists across restarts via a local SQLite database.
//
// Security note: credentials are stored in the local SQLite file
// (data/wa-session.db). Protect that file with appropriate filesystem
// permissions in production.
package consoleapi

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types/events"
	waLog "go.mau.fi/whatsmeow/util/log"
	_ "modernc.org/sqlite" // pure-Go SQLite driver, registered as "sqlite"
	"go.uber.org/zap"
)

// ─── State types ─────────────────────────────────────────────────────────────

// WASessionState is the connection state of the WhatsApp live session.
type WASessionState string

const (
	WAStateDisconnected WASessionState = "disconnected"
	WAStateConnecting   WASessionState = "connecting"
	WAStateQRReady      WASessionState = "qr_ready"
	WAStateConnected    WASessionState = "connected"
)

// ─── Message types ───────────────────────────────────────────────────────────

// WAMessage is an intercepted WhatsApp message stored in the ring buffer.
type WAMessage struct {
	ID        string `json:"id"`
	Chat      string `json:"chat"`      // JID of the chat (E.164@s.whatsapp.net or group@g.us)
	Sender    string `json:"sender"`    // phone number of sender
	Content   string `json:"content"`   // text body, truncated to 500 chars
	Timestamp string `json:"timestamp"` // RFC3339
	HasMedia  bool   `json:"has_media"`
	FromMe    bool   `json:"from_me"`
	IsGroup   bool   `json:"is_group"`
}

// ─── Response shapes ─────────────────────────────────────────────────────────

// WAStatusResponse is the JSON body returned by the status endpoint.
type WAStatusResponse struct {
	State          WASessionState `json:"state"`
	Phone          string         `json:"phone,omitempty"`           // E.164 (without +) when connected
	Name           string         `json:"name,omitempty"`            // WhatsApp display name
	ConnectedSince string         `json:"connected_since,omitempty"` // RFC3339
	MessageCount   int            `json:"message_count"`
}

// WAQRResponse is the JSON body returned by the QR endpoint.
type WAQRResponse struct {
	State     WASessionState `json:"state"`
	QRImage   string         `json:"qr_image,omitempty"`   // data:image/png;base64,...
	ExpiresAt string         `json:"expires_at,omitempty"` // RFC3339
}

// WAMessagesResponse is the JSON body returned by the messages endpoint.
type WAMessagesResponse struct {
	Messages []WAMessage `json:"messages"`
	Total    int         `json:"total"`
}

// ─── Session manager ─────────────────────────────────────────────────────────

const (
	waMaxMessages = 200
	waDBFile      = "data/wa-session.db"
)

// waSession manages a WhatsApp multi-device linked session.
// All exported state is protected by mu; the message ring-buffer uses msgMu.
type waSession struct {
	mu        sync.RWMutex
	client    *whatsmeow.Client
	container *sqlstore.Container
	db        *sql.DB

	state          WASessionState
	qrImage        string    // current QR as data:image/png;base64,...
	qrExpiry       time.Time // when the current QR code expires
	phone          string    // E.164 (without +) when connected
	name           string    // WhatsApp display name
	connectedSince time.Time

	msgMu    sync.RWMutex
	messages []WAMessage // ring buffer, newest at end

	logger   *zap.Logger
	ctx      context.Context    //nolint:containedctx
	cancel   context.CancelFunc

	// qrDoneCh is closed by the QR goroutine to signal completion.
	qrDoneCh chan struct{}
}

// newWASession opens the session database and returns a waSession.
// Returns nil if the database cannot be opened (non-fatal: warn and continue).
func newWASession(logger *zap.Logger) *waSession {
	// _pragma=foreign_keys(1) is applied per-connection by modernc.org/sqlite.
	// SetMaxOpenConns(1) ensures a single SQLite connection (WAL not needed for WA).
	db, err := sql.Open("sqlite", "file:"+waDBFile+"?_pragma=foreign_keys(1)")
	if err != nil {
		logger.Warn("whatsapp: cannot open session db", zap.String("path", waDBFile), zap.Error(err))
		return nil
	}
	db.SetMaxOpenConns(1)
	// Use "sqlite3" as the dialect so whatsmeow uses AUTOINCREMENT (SQLite3 syntax).
	container := sqlstore.NewWithDB(db, "sqlite3", waLog.Noop)
	if err := container.Upgrade(context.Background()); err != nil {
		db.Close()
		logger.Warn("whatsapp: session db upgrade failed", zap.Error(err))
		return nil
	}
	return &waSession{
		state:     WAStateDisconnected,
		container: container,
		db:        db,
		logger:    logger,
		qrDoneCh:  make(chan struct{}),
	}
}

// Start is called once on server startup. If a stored session exists it
// reconnects automatically; otherwise it waits for the user to click Connect.
func (ws *waSession) Start(ctx context.Context) {
	ws.ctx, ws.cancel = context.WithCancel(ctx)

	deviceStore, err := ws.container.GetFirstDevice(ctx)
	if err != nil || deviceStore.ID == nil {
		ws.setState(WAStateDisconnected)
		return // not paired yet
	}
	if err := ws.connectWithDevice(deviceStore); err != nil {
		ws.logger.Warn("whatsapp: auto-reconnect failed", zap.Error(err))
		ws.setState(WAStateDisconnected)
	}
}

// Stop disconnects the client and closes the database.
func (ws *waSession) Stop() {
	if ws.cancel != nil {
		ws.cancel()
	}
	ws.mu.Lock()
	if ws.client != nil {
		ws.client.Disconnect()
	}
	ws.mu.Unlock()
	if ws.db != nil {
		_ = ws.db.Close()
	}
}

// Connect initiates QR pairing for a fresh session or reconnects an existing one.
// It is idempotent; calling it while already connected or connecting is a no-op.
func (ws *waSession) Connect() error {
	ws.mu.RLock()
	cur := ws.state
	ws.mu.RUnlock()
	if cur == WAStateConnected || cur == WAStateConnecting || cur == WAStateQRReady {
		return nil
	}

	deviceStore, err := ws.container.GetFirstDevice(ws.ctx)
	if err != nil {
		return fmt.Errorf("whatsapp: get device: %w", err)
	}
	if deviceStore.ID != nil {
		return ws.connectWithDevice(deviceStore)
	}
	return ws.startQRPairing()
}

// Logout terminates the session, deletes stored credentials, and resets state.
func (ws *waSession) Logout() error {
	ws.mu.Lock()
	client := ws.client
	ws.mu.Unlock()

	if client != nil {
		// Best-effort server-side logout.
		_ = client.Logout(ws.ctx)
		client.Disconnect()
	}

	// Remove stored device credentials from the database.
	deviceStore, err := ws.container.GetFirstDevice(ws.ctx)
	if err == nil && deviceStore.ID != nil {
		_ = ws.container.DeleteDevice(ws.ctx, deviceStore)
	}

	ws.mu.Lock()
	ws.client = nil
	ws.state = WAStateDisconnected
	ws.phone = ""
	ws.name = ""
	ws.qrImage = ""
	ws.connectedSince = time.Time{}
	ws.mu.Unlock()

	ws.msgMu.Lock()
	ws.messages = nil
	ws.msgMu.Unlock()
	return nil
}

// connectWithDevice creates a new whatsmeow client using the stored device and connects.
func (ws *waSession) connectWithDevice(deviceStore *store.Device) error {
	ws.setState(WAStateConnecting)
	client := whatsmeow.NewClient(deviceStore, waLog.Noop)
	client.AddEventHandler(ws.handleEvent)
	ws.mu.Lock()
	ws.client = client
	ws.mu.Unlock()
	if err := client.Connect(); err != nil {
		ws.setState(WAStateDisconnected)
		return fmt.Errorf("whatsapp: connect: %w", err)
	}
	return nil
}

// startQRPairing creates a new (unpaired) device, starts the WA connection, and
// launches a goroutine to relay QR codes from whatsmeow into the session state.
func (ws *waSession) startQRPairing() error {
	ws.setState(WAStateConnecting)

	deviceStore := ws.container.NewDevice()
	client := whatsmeow.NewClient(deviceStore, waLog.Noop)
	client.AddEventHandler(ws.handleEvent)

	ws.mu.Lock()
	ws.client = client
	ws.qrDoneCh = make(chan struct{})
	doneCh := ws.qrDoneCh
	ws.mu.Unlock()

	qrChan, err := client.GetQRChannel(ws.ctx)
	if err != nil {
		ws.setState(WAStateDisconnected)
		return fmt.Errorf("whatsapp: get qr channel: %w", err)
	}
	if err := client.Connect(); err != nil {
		ws.setState(WAStateDisconnected)
		return fmt.Errorf("whatsapp: connect for qr: %w", err)
	}

	go func() {
		defer close(doneCh)
		for {
			select {
			case <-ws.ctx.Done():
				return
			case item, ok := <-qrChan:
				if !ok {
					return
				}
				switch item.Event {
				case whatsmeow.QRChannelEventCode:
					png, err := qrcode.Encode(item.Code, qrcode.Medium, 300)
					if err != nil {
						ws.logger.Warn("whatsapp: qr encode failed", zap.Error(err))
						continue
					}
					dataURL := "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
					ws.mu.Lock()
					ws.qrImage = dataURL
					ws.qrExpiry = time.Now().Add(item.Timeout)
					ws.state = WAStateQRReady
					ws.mu.Unlock()

				case "success":
					ws.mu.Lock()
					ws.qrImage = ""
					ws.state = WAStateConnected
					ws.mu.Unlock()
					return

				default: // timeout, err-*, etc.
					ws.mu.Lock()
					ws.qrImage = ""
					ws.state = WAStateDisconnected
					ws.mu.Unlock()
					return
				}
			}
		}
	}()
	return nil
}

// handleEvent is the whatsmeow event handler registered with the client.
func (ws *waSession) handleEvent(evt interface{}) {
	switch v := evt.(type) {
	case *events.Connected:
		ws.mu.Lock()
		ws.state = WAStateConnected
		ws.connectedSince = time.Now()
		ws.qrImage = ""
		if ws.client != nil && ws.client.Store.ID != nil {
			ws.phone = ws.client.Store.ID.User
		}
		ws.mu.Unlock()
		ws.logger.Info("whatsapp: session connected", zap.String("phone", ws.phone))

	case *events.Disconnected:
		ws.mu.Lock()
		// Only reset if not in QR state (don't clobber QR while pairing).
		if ws.state == WAStateConnected || ws.state == WAStateConnecting {
			ws.state = WAStateDisconnected
		}
		ws.mu.Unlock()

	case *events.LoggedOut:
		ws.mu.Lock()
		ws.state = WAStateDisconnected
		ws.phone = ""
		ws.qrImage = ""
		ws.mu.Unlock()
		ws.logger.Info("whatsapp: session logged out")

	case *events.Message:
		ws.interceptMessage(v)
	}
}

// interceptMessage converts a whatsmeow Message event into a WAMessage and
// appends it to the ring buffer.
func (ws *waSession) interceptMessage(v *events.Message) {
	// Skip historical messages delivered on reconnect (older than 60s).
	if time.Since(v.Info.Timestamp) > 60*time.Second {
		return
	}

	body := ""
	if c := v.Message.GetConversation(); c != "" {
		body = c
	} else if ext := v.Message.GetExtendedTextMessage(); ext != nil {
		body = ext.GetText()
	} else if caption := v.Message.GetImageMessage().GetCaption(); caption != "" {
		body = caption
	}
	if len(body) > 500 {
		body = body[:500] + "…"
	}

	hasMedia := v.Message.GetImageMessage() != nil ||
		v.Message.GetVideoMessage() != nil ||
		v.Message.GetAudioMessage() != nil ||
		v.Message.GetDocumentMessage() != nil ||
		v.Message.GetStickerMessage() != nil

	msg := WAMessage{
		ID:        string(v.Info.ID),
		Chat:      v.Info.Chat.String(),
		Sender:    v.Info.Sender.User,
		Content:   body,
		Timestamp: v.Info.Timestamp.Format(time.RFC3339),
		HasMedia:  hasMedia,
		FromMe:    v.Info.IsFromMe,
		IsGroup:   v.Info.IsGroup,
	}
	ws.appendMessage(msg)
}

func (ws *waSession) appendMessage(msg WAMessage) {
	ws.msgMu.Lock()
	defer ws.msgMu.Unlock()
	ws.messages = append(ws.messages, msg)
	if len(ws.messages) > waMaxMessages {
		ws.messages = ws.messages[len(ws.messages)-waMaxMessages:]
	}
}

func (ws *waSession) setState(state WASessionState) {
	ws.mu.Lock()
	ws.state = state
	ws.mu.Unlock()
}

// Status returns a snapshot of the current session state.
func (ws *waSession) Status() WAStatusResponse {
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	ws.msgMu.RLock()
	msgCount := len(ws.messages)
	ws.msgMu.RUnlock()

	r := WAStatusResponse{
		State:        ws.state,
		Phone:        ws.phone,
		Name:         ws.name,
		MessageCount: msgCount,
	}
	if !ws.connectedSince.IsZero() {
		r.ConnectedSince = ws.connectedSince.Format(time.RFC3339)
	}
	return r
}

// QR returns the current QR code data URL and expiry.
func (ws *waSession) QR() WAQRResponse {
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	r := WAQRResponse{State: ws.state}
	if ws.qrImage != "" {
		r.QRImage = ws.qrImage
		r.ExpiresAt = ws.qrExpiry.Format(time.RFC3339)
	}
	return r
}

// Messages returns intercepted messages in reverse-chronological order.
func (ws *waSession) Messages() WAMessagesResponse {
	ws.msgMu.RLock()
	defer ws.msgMu.RUnlock()
	msgs := make([]WAMessage, len(ws.messages))
	copy(msgs, ws.messages)
	// Reverse to newest-first.
	for i, j := 0, len(msgs)-1; i < j; i, j = i+1, j-1 {
		msgs[i], msgs[j] = msgs[j], msgs[i]
	}
	return WAMessagesResponse{Messages: msgs, Total: len(msgs)}
}

// ─── HTTP handlers ────────────────────────────────────────────────────────────

// handleWAStatus returns the current session state and phone number.
// GET /api/v1/commsguard/whatsapp/status
func (s *Server) handleWAStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if s.waSession == nil {
		_ = json.NewEncoder(w).Encode(WAStatusResponse{State: WAStateDisconnected})
		return
	}
	_ = json.NewEncoder(w).Encode(s.waSession.Status())
}

// handleWAQR returns the current QR code PNG as a base64 data URL.
// GET /api/v1/commsguard/whatsapp/qr
func (s *Server) handleWAQR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if s.waSession == nil {
		_ = json.NewEncoder(w).Encode(WAQRResponse{State: WAStateDisconnected})
		return
	}
	_ = json.NewEncoder(w).Encode(s.waSession.QR())
}

// handleWAMessages returns the intercepted message ring-buffer (newest first).
// GET /api/v1/commsguard/whatsapp/messages
func (s *Server) handleWAMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if s.waSession == nil {
		_ = json.NewEncoder(w).Encode(WAMessagesResponse{Messages: []WAMessage{}, Total: 0})
		return
	}
	_ = json.NewEncoder(w).Encode(s.waSession.Messages())
}

// handleWAConnect initiates QR pairing or reconnects an existing session.
// POST /api/v1/commsguard/whatsapp/connect
func (s *Server) handleWAConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.waSession == nil {
		http.Error(w, "whatsapp session unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := s.waSession.Connect(); err != nil {
		// If already connected / alreadyConnected, treat as success.
		if strings.Contains(err.Error(), "already connected") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "connected"})
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "initiated"})
}

// handleWALogout terminates the WA session and deletes stored credentials.
// POST /api/v1/commsguard/whatsapp/logout
func (s *Server) handleWALogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.waSession != nil {
		_ = s.waSession.Logout()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "logged_out"})
}
