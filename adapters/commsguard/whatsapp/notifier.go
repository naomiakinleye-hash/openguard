// Package whatsapp implements the CommsGuard WhatsApp Business API adapter.
package whatsapp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	common "github.com/DiniMuhd7/openguard/adapters/commsguard/common"
	whatsmeow "go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

const wbaGraphBase = "https://graph.facebook.com/v19.0"

// WhatsAppNotifier implements common.Notifier for WhatsApp.
//
// It supports two delivery modes, selected at construction time:
//
//  1. WhatsApp Business API (WBA) — uses accessToken + phoneNumberID to send
//     a warning via the cloud Graph API. Revocation is not available on WBA
//     for consumer P2P messages, so Intercept returns ErrInterceptUnsupported
//     in this mode.
//
//  2. Linked-device session (whatsmeow) — uses an authenticated *whatsmeow.Client
//     to both revoke (RevokeMessage) and send (SendMessage) messages at the
//     transport layer. Enables true pre-read interception for consumer sessions.
//     When a whatsmeow client is present it is preferred for all operations;
//     WBA credentials are used as a fallback for Notify only.
type WhatsAppNotifier struct {
	// WBA credentials — used for Notify when no whatsmeow client is set.
	accessToken   string
	phoneNumberID string
	httpClient    *http.Client

	// Optional linked-device session — enables Intercept + native SendMessage.
	client *whatsmeow.Client

	logger *zap.Logger
}

// NewWhatsAppNotifier creates a WhatsAppNotifier that sends warnings via the
// WhatsApp Business API (cloud) using accessToken and phoneNumberID.
//
// To also enable linked-device interception (RevokeMessage), call
// WithLinkedDeviceClient after construction.
func NewWhatsAppNotifier(accessToken, phoneNumberID string, logger *zap.Logger) *WhatsAppNotifier {
	return &WhatsAppNotifier{
		accessToken:   accessToken,
		phoneNumberID: phoneNumberID,
		httpClient:    &http.Client{},
		logger:        logger,
	}
}

// WithLinkedDeviceClient attaches an authenticated whatsmeow.Client to the
// notifier. When set, Intercept will call RevokeMessage and Notify will call
// SendMessage directly over the linked-device session instead of the WBA API.
func (n *WhatsAppNotifier) WithLinkedDeviceClient(client *whatsmeow.Client) *WhatsAppNotifier {
	n.client = client
	return n
}

// Channel returns "whatsapp".
func (n *WhatsAppNotifier) Channel() string { return "whatsapp" }

// Intercept attempts to revoke (delete) the malicious message.
//
// When a whatsmeow client is configured, it calls RevokeMessage on the
// linked-device session, which removes the message from both sender and
// recipient devices.
//
// Without a whatsmeow client, WBA does not expose a revocation API for
// inbound P2P consumer messages, so ErrInterceptUnsupported is returned.
func (n *WhatsAppNotifier) Intercept(ctx context.Context, event *common.CommsEvent) error {
	if n.client == nil {
		return common.ErrInterceptUnsupported
	}

	chatJID, err := parsePhoneJID(event.RecipientID)
	if err != nil {
		return fmt.Errorf("whatsapp notifier: parse recipient JID: %w", err)
	}

	msgID := types.MessageID(event.MessageID)
	if _, err := n.client.RevokeMessage(ctx, chatJID, msgID); err != nil {
		return fmt.Errorf("whatsapp notifier: revoke message %s: %w", event.MessageID, err)
	}

	n.logger.Info("whatsapp notifier: message revoked",
		zap.String("message_id", event.MessageID),
		zap.String("chat", event.RecipientID),
	)
	return nil
}

// Notify sends a warning message to the recipient of the malicious communication.
//
// When a whatsmeow client is configured it uses SendMessage on the linked-device
// session. Otherwise it calls the WhatsApp Business API (Graph API).
func (n *WhatsAppNotifier) Notify(ctx context.Context, event *common.CommsEvent, msg string) error {
	if msg == "" {
		msg = common.DefaultNotifyMessage
	}

	if n.client != nil {
		return n.notifyViaLinkedDevice(ctx, event, msg)
	}
	return n.notifyViaBusinessAPI(ctx, event, msg)
}

// notifyViaLinkedDevice sends the warning using the whatsmeow session.
func (n *WhatsAppNotifier) notifyViaLinkedDevice(ctx context.Context, event *common.CommsEvent, msg string) error {
	recipientJID, err := parsePhoneJID(event.RecipientID)
	if err != nil {
		return fmt.Errorf("whatsapp notifier: parse recipient JID: %w", err)
	}

	_, err = n.client.SendMessage(ctx, recipientJID, &waE2E.Message{
		Conversation: proto.String(msg),
	})
	if err != nil {
		return fmt.Errorf("whatsapp notifier: send message to %s: %w", event.RecipientID, err)
	}

	n.logger.Info("whatsapp notifier: warning sent via linked device",
		zap.String("recipient", event.RecipientID),
		zap.String("event_id", event.MessageID),
	)
	return nil
}

// notifyViaBusinessAPI sends the warning via the WhatsApp Business API.
func (n *WhatsAppNotifier) notifyViaBusinessAPI(ctx context.Context, event *common.CommsEvent, msg string) error {
	if n.accessToken == "" || n.phoneNumberID == "" {
		return fmt.Errorf("whatsapp notifier: WBA credentials not configured")
	}

	// RecipientID on WBA events is the phone_number_id of the receiving
	// business number. The sender's phone number is in SenderID — we notify
	// the human sender that their message was flagged.
	// When the event flows as consumer→business, SenderID is the consumer
	// phone; when business→consumer, RecipientID is the consumer phone.
	// Use SenderID for the "warn the intended victim" path.
	toPhone := event.SenderID
	if toPhone == "" {
		toPhone = event.RecipientID
	}

	body := map[string]interface{}{
		"messaging_product": "whatsapp",
		"to":                toPhone,
		"type":              "text",
		"text":              map[string]string{"body": msg},
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("whatsapp notifier: marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/%s/messages", wbaGraphBase, n.phoneNumberID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("whatsapp notifier: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+n.accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("whatsapp notifier: WBA request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("whatsapp notifier: WBA returned %d: %s", resp.StatusCode, string(respBody))
	}

	n.logger.Info("whatsapp notifier: warning sent via WBA",
		zap.String("to", toPhone),
		zap.String("event_id", event.MessageID),
	)
	return nil
}

// parsePhoneJID converts a phone number string (e.g. "15550001234") to a
// WhatsApp JID using the default user server.
func parsePhoneJID(phone string) (types.JID, error) {
	phone = strings.TrimPrefix(phone, "+")
	if phone == "" {
		return types.JID{}, fmt.Errorf("empty phone number")
	}
	// Try full JID parse first (handles "1234567890@s.whatsapp.net" format).
	if strings.Contains(phone, "@") {
		return types.ParseJID(phone)
	}
	return types.NewJID(phone, types.DefaultUserServer), nil
}
