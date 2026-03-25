// Package telegram implements the CommsGuard Telegram Bot API adapter.
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	common "github.com/DiniMuhd7/openguard/adapters/commsguard/common"
	"go.uber.org/zap"
)

const telegramAPIBase = "https://api.telegram.org"

// TelegramNotifier implements common.Notifier for the Telegram Bot API.
//
// Intercept calls deleteMessage to remove the malicious message from the chat
// (requires the bot to have admin/delete rights in groups; not possible in
// private DMs where the bot is not a party).
//
// Notify calls sendMessage to deliver a warning to the same chat the malicious
// message originated in.
type TelegramNotifier struct {
	botToken   string
	httpClient *http.Client
	logger     *zap.Logger
}

// NewTelegramNotifier creates a TelegramNotifier using the given bot token.
func NewTelegramNotifier(botToken string, logger *zap.Logger) *TelegramNotifier {
	return &TelegramNotifier{
		botToken:   botToken,
		httpClient: &http.Client{},
		logger:     logger,
	}
}

// Channel returns "telegram".
func (n *TelegramNotifier) Channel() string { return "telegram" }

// Intercept calls the Telegram Bot API deleteMessage endpoint to remove the
// malicious message from the chat.
//
// This succeeds in groups and supergroups where the bot has been granted
// admin rights with the can_delete_messages permission. In private DMs the
// bot cannot delete messages sent by other users; in that case the API
// returns an error which is wrapped and returned to the caller — Notify will
// still execute with the warning.
func (n *TelegramNotifier) Intercept(ctx context.Context, event *common.CommsEvent) error {
	if n.botToken == "" {
		return common.ErrInterceptUnsupported
	}

	payload := map[string]interface{}{
		"chat_id":    event.RecipientID,
		"message_id": event.MessageID,
	}
	if err := n.callBotAPI(ctx, "deleteMessage", payload, nil); err != nil {
		return fmt.Errorf("telegram notifier: delete message %s in chat %s: %w",
			event.MessageID, event.RecipientID, err)
	}

	n.logger.Info("telegram notifier: message deleted",
		zap.String("message_id", event.MessageID),
		zap.String("chat_id", event.RecipientID),
	)
	return nil
}

// Notify sends a warning message to the chat where the malicious message was
// received. The bot must have send-message rights in the target chat.
func (n *TelegramNotifier) Notify(ctx context.Context, event *common.CommsEvent, msg string) error {
	if n.botToken == "" {
		return fmt.Errorf("telegram notifier: bot token not configured")
	}
	if msg == "" {
		msg = common.DefaultNotifyMessage
	}

	payload := map[string]interface{}{
		"chat_id":    event.RecipientID,
		"text":       msg,
		"parse_mode": "HTML",
	}
	if err := n.callBotAPI(ctx, "sendMessage", payload, nil); err != nil {
		return fmt.Errorf("telegram notifier: send message to chat %s: %w", event.RecipientID, err)
	}

	n.logger.Info("telegram notifier: warning sent",
		zap.String("chat_id", event.RecipientID),
		zap.String("event_id", event.MessageID),
	)
	return nil
}

// callBotAPI is a helper that POSTs to api.telegram.org/bot{token}/{method}
// and decodes the response. If result is non-nil and the Telegram ok field is
// true, the result field is decoded into it.
func (n *TelegramNotifier) callBotAPI(ctx context.Context, method string, payload map[string]interface{}, result interface{}) error {
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	url := fmt.Sprintf("%s/bot%s/%s", telegramAPIBase, n.botToken, method)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	var tgResp struct {
		OK          bool            `json:"ok"`
		Description string          `json:"description"`
		Result      json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(respBody, &tgResp); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}
	if !tgResp.OK {
		return fmt.Errorf("telegram API error: %s", tgResp.Description)
	}
	if result != nil && len(tgResp.Result) > 0 {
		if err := json.Unmarshal(tgResp.Result, result); err != nil {
			return fmt.Errorf("parse result: %w", err)
		}
	}
	return nil
}
