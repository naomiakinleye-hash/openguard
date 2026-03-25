package messenger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/commsguard/common"
	"go.uber.org/zap"
)

// MessengerNotifier implements common.Notifier for the Facebook Messenger channel.
//
// Intercept is not supported: the Messenger Platform does not expose a
// pre-delivery suppression API for messages sent by external users.
//
// Notify sends a text message to the recipient's Page-Scoped User ID (PSID)
// via the Send API (POST /v19.0/me/messages).
type MessengerNotifier struct {
	pageAccessToken string
	httpClient      *http.Client
	logger          *zap.Logger
}

// NewMessengerNotifier constructs a MessengerNotifier.
//
//   - pageAccessToken – Facebook Page access token with the pages_messaging permission.
func NewMessengerNotifier(pageAccessToken string, logger *zap.Logger) *MessengerNotifier {
	return &MessengerNotifier{
		pageAccessToken: pageAccessToken,
		httpClient:      &http.Client{Timeout: 10 * time.Second},
		logger:          logger,
	}
}

// Channel returns "messenger".
func (n *MessengerNotifier) Channel() string { return "messenger" }

// Intercept always returns ErrInterceptUnsupported.
//
// The Messenger Platform does not provide a pre-delivery suppression hook
// for messages originating from users outside the page.
func (n *MessengerNotifier) Intercept(_ context.Context, _ *common.CommsEvent) error {
	return common.ErrInterceptUnsupported
}

// Notify delivers a plain-text warning to event.RecipientID (the recipient's PSID)
// via the Messenger Send API.
func (n *MessengerNotifier) Notify(ctx context.Context, event *common.CommsEvent, msg string) error {
	payload := map[string]any{
		"recipient": map[string]any{"id": event.RecipientID},
		"message":   map[string]any{"text": msg},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("messenger notifier: marshal payload: %w", err)
	}

	endpoint := "https://graph.facebook.com/v19.0/me/messages"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("messenger notifier: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+n.pageAccessToken)

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("messenger notifier: POST messages: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		var apiErr struct {
			Error struct {
				Message string `json:"message"`
				Code    int    `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(raw, &apiErr)
		n.logger.Warn("messenger notifier: API error",
			zap.Int("status", resp.StatusCode),
			zap.Int("fb_code", apiErr.Error.Code),
			zap.String("message", apiErr.Error.Message),
		)
		return fmt.Errorf("messenger notifier: API responded %d: %s", resp.StatusCode, apiErr.Error.Message)
	}

	n.logger.Info("messenger notifier: warning message sent",
		zap.String("message_id", event.MessageID),
		zap.String("recipient_psid", event.RecipientID),
	)
	return nil
}
