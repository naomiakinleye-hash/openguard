package twitter

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

// TwitterNotifier implements common.Notifier for the Twitter/X channel.
//
// Intercept is not supported: the Twitter API does not provide a mechanism
// for one user to delete or suppress another user's direct message before
// the recipient reads it.
//
// Notify sends a direct message to the recipient via the Twitter v2 DM API
// (POST /2/dm_conversations).  The bearer token must carry the dm.write scope
// with user-context authorization (OAuth 2.0 PKCE or OAuth 1.0a user context).
type TwitterNotifier struct {
	bearerToken string
	httpClient  *http.Client
	logger      *zap.Logger
}

// NewTwitterNotifier constructs a TwitterNotifier.
//
//   - bearerToken – OAuth 2.0 user-context access token with dm.write scope.
func NewTwitterNotifier(bearerToken string, logger *zap.Logger) *TwitterNotifier {
	return &TwitterNotifier{
		bearerToken: bearerToken,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
		logger:      logger,
	}
}

// Channel returns "twitter".
func (n *TwitterNotifier) Channel() string { return "twitter" }

// Intercept always returns ErrInterceptUnsupported.
//
// Twitter/X does not expose a pre-delivery suppression API for DMs sent by
// external users; only the sender can delete their own messages.
func (n *TwitterNotifier) Intercept(_ context.Context, _ *common.CommsEvent) error {
	return common.ErrInterceptUnsupported
}

// Notify sends a direct message to event.RecipientID (the recipient's Twitter
// user ID) using the Twitter v2 DM API.
//
// If a conversation already exists between the bot account and the recipient
// the API reuses it; otherwise a new one-on-one conversation is created.
func (n *TwitterNotifier) Notify(ctx context.Context, event *common.CommsEvent, msg string) error {
	payload := map[string]any{
		"participant_ids": []string{event.RecipientID},
		"message":        map[string]any{"text": msg},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("twitter notifier: marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		"https://api.twitter.com/2/dm_conversations",
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("twitter notifier: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+n.bearerToken)

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("twitter notifier: POST dm_conversations: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		var apiErr struct {
			Title  string `json:"title"`
			Detail string `json:"detail"`
		}
		_ = json.Unmarshal(raw, &apiErr)
		n.logger.Warn("twitter notifier: API error",
			zap.Int("status", resp.StatusCode),
			zap.String("title", apiErr.Title),
			zap.String("detail", apiErr.Detail),
		)
		return fmt.Errorf("twitter notifier: API responded %d: %s", resp.StatusCode, apiErr.Detail)
	}

	n.logger.Info("twitter notifier: warning DM sent",
		zap.String("message_id", event.MessageID),
		zap.String("recipient_id", event.RecipientID),
	)
	return nil
}
