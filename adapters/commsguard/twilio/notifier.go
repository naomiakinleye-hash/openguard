package twilio

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/commsguard/common"
	"go.uber.org/zap"
)

// TwilioNotifier implements common.Notifier for the Twilio SMS channel.
//
// Intercept is not supported for SMS: by the time the Twilio webhook fires
// the message has already been handed off to the carrier.  Twilio does not
// provide a pre-delivery suppression hook for inbound SMS.
//
// Notify sends a plain-text warning SMS to the recipient using the Twilio
// Messaging REST API (POST /Accounts/{SID}/Messages.json).
type TwilioNotifier struct {
	accountSID string
	authToken  string
	fromNumber string // E.164 format, e.g. "+14155551234"
	httpClient *http.Client
	logger     *zap.Logger
}

// NewTwilioNotifier constructs a TwilioNotifier.
//
//   - accountSID  – Twilio Account SID
//   - authToken   – Twilio Auth Token (used for HTTP Basic auth)
//   - fromNumber  – the Twilio number to send warnings from (E.164)
func NewTwilioNotifier(accountSID, authToken, fromNumber string, logger *zap.Logger) *TwilioNotifier {
	return &TwilioNotifier{
		accountSID: accountSID,
		authToken:  authToken,
		fromNumber: fromNumber,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		logger:     logger,
	}
}

// Channel returns "twilio".
func (n *TwilioNotifier) Channel() string { return "twilio" }

// Intercept always returns ErrInterceptUnsupported.
//
// Twilio inbound SMS webhooks fire after the carrier has already delivered
// the message; there is no pre-delivery suppression API available.
func (n *TwilioNotifier) Intercept(_ context.Context, _ *common.CommsEvent) error {
	return common.ErrInterceptUnsupported
}

// Notify sends a warning SMS to event.RecipientID via the Twilio Messages API.
//
// event.RecipientID must be the recipient's phone number in E.164 format.
func (n *TwilioNotifier) Notify(ctx context.Context, event *common.CommsEvent, msg string) error {
	if n.fromNumber == "" {
		return fmt.Errorf("twilio notifier: from_number not configured")
	}

	endpoint := fmt.Sprintf(
		"https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json",
		n.accountSID,
	)

	body := url.Values{}
	body.Set("From", n.fromNumber)
	body.Set("To", event.RecipientID)
	body.Set("Body", msg)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return fmt.Errorf("twilio notifier: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(n.accountSID, n.authToken)

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("twilio notifier: POST messages: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		var apiErr struct {
			Message string `json:"message"`
			Code    int    `json:"code"`
		}
		_ = json.Unmarshal(raw, &apiErr)
		n.logger.Warn("twilio notifier: API error",
			zap.Int("status", resp.StatusCode),
			zap.Int("twilio_code", apiErr.Code),
			zap.String("message", apiErr.Message),
		)
		return fmt.Errorf("twilio notifier: API responded %d: %s", resp.StatusCode, apiErr.Message)
	}

	n.logger.Info("twilio notifier: warning SMS sent",
		zap.String("message_id", event.MessageID),
		zap.String("recipient", event.RecipientID),
	)
	return nil
}
