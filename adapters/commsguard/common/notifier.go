// Package commsguardcommon provides shared types and utilities for the CommsGuard sensor.
package commsguardcommon

import (
	"context"
	"errors"
)

// ErrInterceptUnsupported is returned by Notifier.Intercept when the channel
// or context does not support pre-delivery message suppression (e.g. Messenger
// private DMs, Twitter DMs where the platform provides no deletion API).
var ErrInterceptUnsupported = errors.New("commsguard: intercept not supported on this channel")

// Notifier sends a warning to the recipient of a malicious message via the
// same channel the message arrived on, and optionally suppresses (intercepts)
// the malicious message before or immediately after it is read.
//
// Implementations are per-channel (WhatsApp, Telegram, Twilio, Messenger,
// Twitter). The CommsGuardSensor holds a registry of Notifiers keyed by
// channel name and dispatches to the correct one after a threat is confirmed.
type Notifier interface {
	// Channel returns the communication channel this notifier handles.
	// Must match CommsEvent.Channel (e.g. "whatsapp", "telegram").
	Channel() string

	// Intercept attempts to suppress or revoke the malicious message before
	// or immediately after delivery.
	//
	// Returns ErrInterceptUnsupported when the channel/context does not allow
	// message deletion. Other errors indicate a transient failure.
	//
	// Intercept is best-effort: callers MUST proceed to Notify even when
	// Intercept fails, so the recipient is always warned regardless of whether
	// the malicious message could be removed.
	Intercept(ctx context.Context, event *CommsEvent) error

	// Notify delivers a plain-language warning to event.RecipientID via the
	// same channel the malicious message arrived on.
	//
	// msg is the human-readable warning body; callers should pass the AI
	// model's ai_summary from CommsEvent.RawData when available, falling back
	// to a generic warning string.
	Notify(ctx context.Context, event *CommsEvent, msg string) error
}

// ResponseEvent is the NATS message format published to the response topic
// (default: "openguard.commsguard.response") by the response-orchestrator
// after evaluating a comms threat and deciding on an action.
//
// The CommsGuardSensor subscribes to this topic and dispatches the appropriate
// Intercept / Notify call on the Notifier registered for the event's channel.
type ResponseEvent struct {
	// EventID is the originating CommsEvent's event_id (used for correlation
	// and audit trail linkage).
	EventID string `json:"event_id"`

	// Channel identifies which channel adapter and notifier should handle
	// this response (e.g. "whatsapp", "telegram").
	Channel string `json:"channel"`

	// SenderID is the threat actor's identifier on the channel (phone number,
	// username, chat ID, etc.).
	SenderID string `json:"sender_id"`

	// RecipientID is the intended recipient to be warned (phone number,
	// chat ID, user ID, etc.).
	RecipientID string `json:"recipient_id"`

	// MessageID is the platform-specific identifier of the malicious message
	// to intercept (delete/revoke). May be empty when interception was
	// already handled inline.
	MessageID string `json:"message_id"`

	// Action controls what the notifier should do.
	// Valid values: "intercept", "notify", "intercept_and_notify".
	Action string `json:"action"`

	// NotifyMessage is the warning text to deliver to the recipient.
	// Callers should populate this with the AI model's ai_summary when
	// available.
	NotifyMessage string `json:"notify_message"`
}

// DefaultNotifyMessage is the fallback warning text used when no AI summary
// is available in the response event.
const DefaultNotifyMessage = "⚠️ OpenGuard Security Alert: A potentially malicious message directed at you has been detected and intercepted. Please do not engage with unexpected links, attachments, or requests for personal information."
