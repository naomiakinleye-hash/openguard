// Package tunnel manages ngrok and Cloudflare Tunnel processes so that the
// CommsGuard webhook server can be reached from the internet without any manual
// port-forwarding or public static IP.
//
// # Supported modes
//
//   - "ngrok"        — starts the ngrok CLI and queries its local agent API at
//     localhost:4040 to obtain the public HTTPS URL.
//   - "cloudflared"  — starts cloudflared quick tunnel and parses its log output
//     for the *.trycloudflare.com URL.
//   - ""             — no tunnel; webhook server is reachable only on LAN/localhost.
//
// # Prerequisites
//
//   ngrok must be installed and available on PATH.
//   For ngrok v3 a free account is required: https://dashboard.ngrok.com/signup
//   Authenticate once with: ngrok config add-authtoken <TOKEN>
//   Alternatively pass NGROK_AUTHTOKEN env var or set NgrokAuthToken in Config.
//
//   cloudflared must be installed and available on PATH (no account needed for
//   quick tunnels): https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/
package tunnel

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Mode selects which tunnel provider to use.
type Mode string

const (
	ModeNone        Mode = ""
	ModeNgrok       Mode = "ngrok"
	ModeCloudflared Mode = "cloudflared"
)

// Tunnel holds the running tunnel process and its discovered public URL.
type Tunnel struct {
	// PublicURL is the externally reachable HTTPS base URL (no trailing slash).
	// e.g. "https://abc123.ngrok-free.app" or "https://word-word.trycloudflare.com"
	PublicURL string

	mode   Mode
	cmd    *exec.Cmd
	logger *zap.Logger
}

// Start launches the requested tunnel provider against localAddr (e.g. "8090" or ":8090")
// and waits up to 30 s for the public URL to become available.
// Returns a *Tunnel whose Stop() method must be called on shutdown.
func Start(ctx context.Context, mode Mode, localAddr string, ngrokAuthToken string, logger *zap.Logger) (*Tunnel, error) {
	port := strings.TrimPrefix(localAddr, ":")

	switch mode {
	case ModeNgrok:
		return startNgrok(ctx, port, ngrokAuthToken, logger)
	case ModeCloudflared:
		return startCloudflared(ctx, port, logger)
	default:
		return nil, fmt.Errorf("tunnel: unknown mode %q (use \"ngrok\" or \"cloudflared\")", mode)
	}
}

// Stop kills the tunnel process. Safe to call on a nil *Tunnel.
func (t *Tunnel) Stop() {
	if t == nil || t.cmd == nil || t.cmd.Process == nil {
		return
	}
	if err := t.cmd.Process.Kill(); err != nil {
		t.logger.Warn("tunnel: process kill error", zap.String("mode", string(t.mode)), zap.Error(err))
	}
}

// ─── ngrok ───────────────────────────────────────────────────────────────────

// ngrokTunnelsResp is the subset of the ngrok local agent API response we need.
type ngrokTunnelsResp struct {
	Tunnels []struct {
		PublicURL string `json:"public_url"`
		Proto     string `json:"proto"`
	} `json:"tunnels"`
}

func startNgrok(ctx context.Context, port, authToken string, logger *zap.Logger) (*Tunnel, error) {
	args := []string{"http", port}
	if authToken != "" {
		args = append(args, "--authtoken="+authToken)
	}

	cmd := exec.CommandContext(ctx, "ngrok", args...)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("tunnel: start ngrok: %w (is ngrok installed and on PATH?)", err)
	}

	logger.Info("tunnel: ngrok process started", zap.String("port", port))

	t := &Tunnel{mode: ModeNgrok, cmd: cmd, logger: logger}

	// Poll the ngrok local agent API (default: localhost:4040) until a tunnel URL appears.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		default:
		}

		url, err := ngrokPublicURL()
		if err == nil && url != "" {
			t.PublicURL = url
			logger.Info("tunnel: ngrok public URL ready",
				zap.String("public_url", url),
				zap.String("port", port),
			)
			printBanner(logger, "ngrok", url)
			return t, nil
		}
		time.Sleep(500 * time.Millisecond)
	}

	t.Stop()
	return nil, fmt.Errorf("tunnel: timed out waiting for ngrok public URL (check ngrok is authenticated and port %s is not in use)", port)
}

// ngrokPublicURL queries the ngrok local agent API and returns the first HTTPS tunnel URL.
func ngrokPublicURL() (string, error) {
	resp, err := http.Get("http://localhost:4040/api/tunnels") //nolint:noctx
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck

	var payload ngrokTunnelsResp
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}

	for _, t := range payload.Tunnels {
		if t.Proto == "https" && strings.HasPrefix(t.PublicURL, "https://") {
			return t.PublicURL, nil
		}
	}
	return "", fmt.Errorf("no https tunnel yet")
}

// ─── cloudflared ──────────────────────────────────────────────────────────────

// cfURLPattern matches the trycloudflare.com HTTPS URL in cloudflared log output.
var cfURLPattern = regexp.MustCompile(`https://[a-zA-Z0-9-]+\.trycloudflare\.com`)

func startCloudflared(ctx context.Context, port string, logger *zap.Logger) (*Tunnel, error) {
	cmd := exec.CommandContext(ctx, "cloudflared", "tunnel", "--url", "http://localhost:"+port, "--no-autoupdate")

	// cloudflared writes the URL to stderr.
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("tunnel: cloudflared stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("tunnel: start cloudflared: %w (is cloudflared installed and on PATH?)", err)
	}

	logger.Info("tunnel: cloudflared process started", zap.String("port", port))

	t := &Tunnel{mode: ModeCloudflared, cmd: cmd, logger: logger}

	// Scan stderr in a goroutine and send the URL once found.
	urlCh := make(chan string, 1)
	go func() {
		defer close(urlCh)
		scanner := bufio.NewScanner(io.TeeReader(stderr, io.Discard))
		for scanner.Scan() {
			line := scanner.Text()
			if m := cfURLPattern.FindString(line); m != "" {
				select {
				case urlCh <- m:
				default:
				}
				// Keep draining so the process doesn't block on stderr.
				for scanner.Scan() {
				}
				return
			}
		}
	}()

	select {
	case publicURL, ok := <-urlCh:
		if !ok || publicURL == "" {
			t.Stop()
			return nil, fmt.Errorf("tunnel: cloudflared exited before a URL was found")
		}
		t.PublicURL = publicURL
		logger.Info("tunnel: cloudflared public URL ready",
			zap.String("public_url", publicURL),
			zap.String("port", port),
		)
		printBanner(logger, "cloudflared", publicURL)
		return t, nil

	case <-time.After(30 * time.Second):
		t.Stop()
		return nil, fmt.Errorf("tunnel: timed out waiting for cloudflared public URL")

	case <-ctx.Done():
		t.Stop()
		return nil, ctx.Err()
	}
}

// ─── helpers ──────────────────────────────────────────────────────────────────

// printBanner emits a prominent, easy-to-spot log line with the public URL and
// the webhook paths for each channel so operators know exactly what to register.
func printBanner(logger *zap.Logger, provider, publicURL string) {
	logger.Info("╔══════════════════════════════════════════════════════════════╗")
	logger.Info("║          CommsGuard — Tunnel Active                          ║",
		zap.String("provider", provider),
	)
	logger.Info("║  Public base URL", zap.String("url", publicURL))
	logger.Info("║")
	logger.Info("║  Register these webhook URLs in each platform's developer console:")
	logger.Info("║  WhatsApp   →  "+publicURL+"/whatsapp/webhook")
	logger.Info("║  Telegram   →  "+publicURL+"/telegram/webhook")
	logger.Info("║  Messenger  →  "+publicURL+"/messenger/webhook")
	logger.Info("║  Twilio SMS →  "+publicURL+"/twilio/sms")
	logger.Info("║  Twilio Voice→  "+publicURL+"/twilio/voice")
	logger.Info("║  Twitter/X  →  "+publicURL+"/twitter/webhook")
	logger.Info("╚══════════════════════════════════════════════════════════════╝")
}
