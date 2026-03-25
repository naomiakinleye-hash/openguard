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
	"os"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	commsguardcommon "github.com/DiniMuhd7/openguard/adapters/commsguard/common"
	nats "github.com/nats-io/nats.go"
	"go.mau.fi/whatsmeow"
	waE2E "go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	waLog "go.mau.fi/whatsmeow/util/log"
	_ "modernc.org/sqlite" // pure-Go SQLite driver, registered as "sqlite"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
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
	ID        string   `json:"id"`
	Chat      string   `json:"chat"`      // JID of the chat (E.164@s.whatsapp.net or group@g.us)
	Sender    string   `json:"sender"`    // phone number of sender
	Content   string   `json:"content"`   // text body, truncated to 500 chars
	Timestamp string   `json:"timestamp"` // RFC3339
	HasMedia  bool     `json:"has_media"`
	FromMe    bool     `json:"from_me"`
	IsGroup   bool     `json:"is_group"`
	IsFlagged bool     `json:"is_flagged"` // true when threat analysis found indicators
	Threats   []string `json:"threats"`    // threat indicator strings from ThreatAnalyzer
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

	// analyzer performs AI-driven threat analysis on intercepted message content.
	analyzer *commsguardcommon.ThreatAnalyzer

	// natsURL is the NATS server URL used to create the event publisher.
	natsURL string
	// publisher publishes CommsEvents to the ingest pipeline via NATS.
	publisher *commsguardcommon.Publisher

	// modelNC is a dedicated NATS connection for the model-gateway AI enricher.
	// Separate from the publisher connection so it can be drained independently.
	modelNC *nats.Conn

	// model-gateway configuration (populated from env vars in newWASession).
	modelGatewayTopic   string
	modelGatewayTimeout time.Duration
	modelGatewayAgentID string
}

// newWASession opens the session database and returns a waSession.
// natsURL is used to create a NATS publisher for the ingest pipeline; pass
// an empty string to disable publishing (detection still runs but events are
// not forwarded to the orchestrator).
// Returns nil if the database cannot be opened (non-fatal: warn and continue).
func newWASession(natsURL string, logger *zap.Logger) *waSession {
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
	// Read model-gateway config from env — same vars used by commsguard-agent.
	mgTopic := os.Getenv("COMMSGUARD_MODEL_GATEWAY_TOPIC")
	if mgTopic == "" {
		mgTopic = "openguard.modelguard.requests"
	}
	mgTimeout := 10 * time.Second
	if v := os.Getenv("COMMSGUARD_MODEL_GATEWAY_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			mgTimeout = d
		}
	}
	mgAgentID := os.Getenv("COMMSGUARD_MODEL_GATEWAY_AGENT_ID")
	if mgAgentID == "" {
		mgAgentID = "commsguard-wa"
	}

	return &waSession{
		state:               WAStateDisconnected,
		container:           container,
		db:                  db,
		logger:              logger,
		qrDoneCh:            make(chan struct{}),
		analyzer:            commsguardcommon.NewThreatAnalyzer(),
		natsURL:             natsURL,
		modelGatewayTopic:   mgTopic,
		modelGatewayTimeout: mgTimeout,
		modelGatewayAgentID: mgAgentID,
	}
}

// Start is called once on server startup. If a stored session exists it
// reconnects automatically; otherwise it waits for the user to click Connect.
func (ws *waSession) Start(ctx context.Context) {
	ws.ctx, ws.cancel = context.WithCancel(ctx)

	// ── Wire NATS publisher for the ingest pipeline ───────────────────────────
	// Events are published to openguard.commsguard.raw so they flow through
	// ingest → detect → response-orchestrator just like webhook-based channels.
	if ws.natsURL != "" {
		pub, err := commsguardcommon.NewPublisher(ws.natsURL, "openguard.commsguard.raw", true, ws.logger)
		if err != nil {
			ws.logger.Warn("whatsapp: NATS publisher unavailable — events will not be forwarded to ingest pipeline",
				zap.String("nats_url", ws.natsURL), zap.Error(err))
		} else {
			ws.publisher = pub
			ws.logger.Info("whatsapp: NATS publisher connected", zap.String("topic", "openguard.commsguard.raw"))
		}
	}

	// ── Wire model-gateway AI enricher ───────────────────────────────────────
	// Connect a dedicated NATS connection and attach a ModelIntelClient so the
	// linked session benefits from the same AI threat classification as the
	// webhook-based CommsGuard adapters.
	if ws.natsURL != "" {
		nc, err := nats.Connect(ws.natsURL,
			nats.Name("openguard-commsguard-wa-intel"),
			nats.MaxReconnects(-1),
		)
		if err != nil {
			ws.logger.Warn("whatsapp: model-gateway NATS connect failed — AI enrichment disabled",
				zap.String("nats_url", ws.natsURL),
				zap.Error(err),
			)
		} else {
			ws.modelNC = nc
			modelClient := commsguardcommon.NewModelIntelClient(
				nc, ws.modelGatewayTopic, ws.modelGatewayTimeout, ws.modelGatewayAgentID, ws.logger,
			)
			ws.analyzer.WithModelIntelClient(modelClient)
			ws.logger.Info("whatsapp: model-gateway AI enrichment enabled",
				zap.String("topic", ws.modelGatewayTopic),
				zap.Duration("timeout", ws.modelGatewayTimeout),
			)
		}
	}

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
	if ws.publisher != nil {
		ws.publisher.Close()
		ws.publisher = nil
	}
	if ws.modelNC != nil {
		_ = ws.modelNC.Drain()
		ws.modelNC = nil
	}
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
// appends it to the ring buffer, publishes it to the ingest pipeline via NATS,
// and runs threat analysis so flagged messages can be acted upon.
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

	// RecipientID is the JID of the chat (individual or group).
	recipientID := v.Info.Chat.String()

	// Build the event for threat analysis and NATS publishing.
	evt := &commsguardcommon.CommsEvent{
		EventType:   "message_received",
		Channel:     "whatsapp",
		Timestamp:   v.Info.Timestamp,
		SenderID:    v.Info.Sender.User,
		RecipientID: recipientID,
		MessageID:   string(v.Info.ID),
		Content:     body,
		RawData:     make(map[string]interface{}),
	}

	// Run threat analysis on the message content.
	var threats []string
	if ws.analyzer != nil && body != "" {
		threats = ws.analyzer.Analyze(evt)
	}
	if threats == nil {
		threats = []string{}
	}

	// Promote event type based on detected indicators so classifyEvent() assigns
	// the correct risk_score and tier when the event is published to NATS.
	if len(threats) > 0 {
		evt.Indicators = threats
		evt.EventType = commsguardcommon.PromoteEventType(evt.EventType, threats)
	}

	// Publish to the ingest pipeline so the orchestrator can respond.
	if ws.publisher != nil {
		if err := ws.publisher.Publish(context.Background(), evt); err != nil {
			ws.logger.Warn("whatsapp: failed to publish event to ingest pipeline",
				zap.String("message_id", evt.MessageID),
				zap.Error(err),
			)
		} else if len(threats) > 0 {
			ws.logger.Info("whatsapp: threat detected — event published",
				zap.String("message_id", evt.MessageID),
				zap.String("sender", evt.SenderID),
				zap.String("event_type", evt.EventType),
				zap.Strings("indicators", threats),
			)
		}
	}

	// Actively intercept: revoke the flagged message and warn the chat.
	if len(threats) > 0 {
		go ws.actOnThreats(v, threats)
	}

	msg := WAMessage{
		ID:        string(v.Info.ID),
		Chat:      v.Info.Chat.String(),
		Sender:    v.Info.Sender.User,
		Content:   body,
		Timestamp: v.Info.Timestamp.Format(time.RFC3339),
		HasMedia:  hasMedia,
		FromMe:    v.Info.IsFromMe,
		IsGroup:   v.Info.IsGroup,
		IsFlagged: len(threats) > 0,
		Threats:   threats,
	}
	ws.appendMessage(msg)
}

// actOnThreats performs the active response for a detected threat:
//  1. Attempts to revoke the malicious message (succeeds for messages sent from
//     this account; best-effort/no-op for messages sent by other contacts).
//  2. Sends a plain-language warning to the same chat so the recipient is alerted
//     regardless of whether the original message could be deleted.
//
// Called in a goroutine from interceptMessage so it does not block event handling.
func (ws *waSession) actOnThreats(v *events.Message, threats []string) {
	ws.mu.RLock()
	client := ws.client
	ws.mu.RUnlock()
	if client == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	chat := v.Info.Chat
	msgID := types.MessageID(v.Info.ID)

	// Step 1 — Revoke the malicious message (best-effort).
	if _, err := client.RevokeMessage(ctx, chat, msgID); err != nil {
		ws.logger.Warn("whatsapp: message revoke failed (best-effort)",
			zap.String("message_id", string(msgID)),
			zap.String("chat", chat.String()),
			zap.Error(err),
		)
	} else {
		ws.logger.Info("whatsapp: malicious message revoked",
			zap.String("message_id", string(msgID)),
			zap.String("chat", chat.String()),
		)
	}

	// Step 2 — Send a warning to the chat.
	summary := strings.Join(threats, ", ")
	warningText := fmt.Sprintf(
		"⚠️ OpenGuard blocked a malicious message from %s. Detected threat(s): %s. Please do not interact with it.",
		v.Info.Sender.User, summary,
	)
	warningMsg := &waE2E.Message{
		Conversation: proto.String(warningText),
	}
	if _, err := client.SendMessage(ctx, chat, warningMsg); err != nil {
		ws.logger.Warn("whatsapp: warning message send failed",
			zap.String("chat", chat.String()),
			zap.Error(err),
		)
	} else {
		ws.logger.Info("whatsapp: warning message sent to chat",
			zap.String("chat", chat.String()),
			zap.Strings("threats", threats),
		)
	}
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
