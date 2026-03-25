// Package main is the entry point for the OpenGuard v5 platform.
package main

import (
"context"
"os"
"os/signal"
"syscall"
"time"

"github.com/joho/godotenv"
"go.opentelemetry.io/otel"
"go.opentelemetry.io/otel/sdk/trace"
"go.uber.org/zap"

consoleapi "github.com/DiniMuhd7/openguard/services/console-api"
auditled "github.com/DiniMuhd7/openguard/services/audit-ledger"
"github.com/DiniMuhd7/openguard/services/detect"
"github.com/DiniMuhd7/openguard/services/ingest"
orchestrator "github.com/DiniMuhd7/openguard/services/response-orchestrator"
policyengine "github.com/DiniMuhd7/openguard/services/policy-engine"

hostguard "github.com/DiniMuhd7/openguard/adapters/hostguard"
hostguardcommon "github.com/DiniMuhd7/openguard/adapters/hostguard/common"

nats "github.com/nats-io/nats.go"
modelagent "github.com/DiniMuhd7/openguard/model-gateway/agent"
)

// incidentSinkAdapter adapts consoleapi.IncidentStore to the orchestrator.IncidentSink interface.
type incidentSinkAdapter struct {
	store *consoleapi.IncidentStore
}

func (a *incidentSinkAdapter) Add(inc *orchestrator.OrchestratorIncident) {
	a.store.Add(&consoleapi.Incident{
		ID:          inc.ID,
		EventID:     inc.EventID,
		Type:        inc.Type,
		Tier:        inc.Tier,
		RiskScore:   inc.RiskScore,
		Status:      inc.Status,
		CreatedAt:   inc.CreatedAt,
		Description: inc.Description,
	})
}

// eventPipeline chains the detection service with the response orchestrator so
// that every ingested event is (1) scored and stored, then (2) dispatched for
// policy evaluation, audit logging, and tier-appropriate response.
type eventPipeline struct {
	detect *detect.Service
	orch   *orchestrator.Orchestrator
}

func (p *eventPipeline) HandleEvent(ctx context.Context, event map[string]interface{}) error {
	// Step 1: score, enrich, and persist the event.
	if err := p.detect.HandleEvent(ctx, event); err != nil {
		return err
	}
	// Step 2: dispatch to the orchestrator for policy evaluation and response.
	// The proposed action is derived from the tier assigned by detection.
	tier, _ := event["tier"].(string)
	proposedAction := "auto_monitor"
	switch tier {
	case "T2":
		proposedAction = "request_approval"
	case "T3":
		proposedAction = "containment"
	case "T4":
		proposedAction = "emergency_lockdown"
	}
	return p.orch.Dispatch(ctx, event, proposedAction)
}

func main() {
// Load .env file if present (silently ignored when absent so production
// deployments that inject env vars directly are unaffected).
_ = godotenv.Load()

logger, err := zap.NewProduction()
if err != nil {
panic("failed to initialize logger: " + err.Error())
}
defer logger.Sync() //nolint:errcheck

logger.Info("OpenGuard v5 starting",
zap.String("version", "5.0.0"),
zap.String("module", "github.com/DiniMuhd7/openguard"),
)

// Initialize OpenTelemetry tracer.
tp := trace.NewTracerProvider()
otel.SetTracerProvider(tp)
defer func() {
if err := tp.Shutdown(context.Background()); err != nil {
logger.Warn("otel: tracer provider shutdown error", zap.Error(err))
}
}()

natsURL := getEnv("NATS_URL", "nats://localhost:4222")
policyDir := getEnv("POLICY_DIR", "./policies")
listenAddr := getEnv("LISTEN_ADDR", ":8080")

// Initialize audit ledger.
ledger := auditled.NewLedger(auditled.Config{
StoragePath: getEnv("AUDIT_STORAGE_PATH", "./data/audit.ndjson"),
}, logger)
if err := ledger.Open(); err != nil {
logger.Warn("audit ledger: could not open storage file", zap.Error(err))
}
defer ledger.Close() //nolint:errcheck

// Initialize event and incident stores.
eventStore := consoleapi.NewEventStore()
incidentStore := consoleapi.NewIncidentStore()

// Initialize policy engine.
pe, err := policyengine.NewEngine(policyengine.Config{
PolicyDir: policyDir,
}, logger)
if err != nil {
logger.Fatal("failed to initialize policy engine", zap.Error(err))
}

// Initialize detection service.
detectSvc := detect.NewService(detect.Config{
RulesDir: getEnv("RULES_DIR", "./rules"),
Sink:     eventStore,
}, logger)

// Initialize response orchestrator.
orch := orchestrator.NewOrchestrator(orchestrator.Config{
ApprovalTimeout: 30 * time.Minute,
IncidentSink:    &incidentSinkAdapter{store: incidentStore},
}, pe, ledger, logger)

// Wire detection + orchestration into a single pipeline handler.
pipeline := &eventPipeline{detect: detectSvc, orch: orch}

// Initialize ingest service.
ingestSvc, err := ingest.NewService(ingest.Config{
NATSUrl:  natsURL,
SchemaPath: getEnv("SCHEMA_PATH", "./schemas/unified-event.schema.json"),
}, pipeline, nil, logger)
if err != nil {
logger.Fatal("failed to initialize ingest service", zap.Error(err))
}

// Initialize console API.
apiServer := consoleapi.NewServer(consoleapi.Config{
ListenAddr: listenAddr,
JWTSecret:  getEnv("JWT_SECRET", "change-me-in-production"),
NATSUrl:    natsURL,
}, ledger, eventStore, incidentStore, logger)

ctx, cancel := context.WithCancel(context.Background())
defer cancel()

// Start all services.
if err := ingestSvc.Start(ctx); err != nil {
logger.Fatal("failed to start ingest service", zap.Error(err))
}
if err := apiServer.Start(ctx); err != nil {
logger.Fatal("failed to start console API", zap.Error(err))
}

// Start HostGuard sensor in-process (direct mode — no NATS required).
// This feeds live host telemetry (processes, resources, network, etc.) directly
// into the ingest → detect → eventStore pipeline so the dashboard shows real data.
sensorCfg := hostguardcommon.DefaultConfig()
hgSensor, hgErr := hostguard.NewSensorDirect(sensorCfg, func(payload []byte) error {
return ingestSvc.Ingest(context.Background(), payload)
}, logger)
if hgErr != nil {
logger.Warn("hostguard sensor: init failed (running without host telemetry)", zap.Error(hgErr))
} else if startErr := hgSensor.Start(ctx); startErr != nil {
logger.Warn("hostguard sensor: start failed (running without host telemetry)", zap.Error(startErr))
} else {
defer hgSensor.Stop() //nolint:errcheck
logger.Info("hostguard sensor: running in-process", zap.String("platform", hgSensor.Platform()))
}

// Start the model-gateway agent in-process. It subscribes to the model
// request topic over the same NATS connection used by the ingest service
// and the console API, so no separate process or binary is required.
stopMG := startModelGateway(ctx, natsURL, logger)
defer stopMG()

logger.Info("OpenGuard v5 running",
zap.String("listen", listenAddr),
zap.String("nats", natsURL),
)

// Wait for shutdown signal.
quit := make(chan os.Signal, 1)
signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
<-quit

logger.Info("OpenGuard v5 shutting down gracefully")
cancel()

shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
defer shutdownCancel()

ingestSvc.Stop()
if err := apiServer.Stop(shutdownCtx); err != nil {
logger.Warn("console API shutdown error", zap.Error(err))
}

logger.Info("OpenGuard v5 stopped")
}

// startModelGateway starts the model-gateway agent in-process using the given
// NATS URL. It returns a stop function that drains the subscriptions on shutdown.
// If no AI provider API key is set the gateway is skipped and the returned stop
// function is a no-op; callers need not check the return value.
func startModelGateway(ctx context.Context, natsURL string, logger *zap.Logger) func() {
cfg := modelagent.DefaultConfig()
cfg.OpenAIKey = os.Getenv("OPENGUARD_OPENAI_API_KEY")
cfg.AnthropicKey = os.Getenv("OPENGUARD_ANTHROPIC_API_KEY")
cfg.GeminiKey = os.Getenv("OPENGUARD_GEMINI_API_KEY")
cfg.ProviderName = getEnv("OPENGUARD_PROVIDER", cfg.ProviderName)
cfg.Strategy = getEnv("OPENGUARD_RISK_STRATEGY", cfg.Strategy)
cfg.SigSecret = os.Getenv("OPENGUARD_MSG_HMAC_SECRET")
cfg.ToolPolicyPath = getEnv("OPENGUARD_TOOL_POLICY_PATH", cfg.ToolPolicyPath)
cfg.AuditPath = getEnv("OPENGUARD_AUDIT_PATH", cfg.AuditPath)

natsConnURL := getEnv("OPENGUARD_NATS_URL", natsURL)
nc, err := nats.Connect(natsConnURL)
if err != nil {
logger.Warn("model-gateway: failed to connect to NATS — AI enrichment disabled",
zap.String("nats_url", natsConnURL), zap.Error(err))
return func() {}
}

stop, err := modelagent.Run(ctx, nc, cfg, logger)
if err != nil {
logger.Warn("model-gateway: failed to start — AI enrichment disabled", zap.Error(err))
nc.Close()
return func() {}
}

return func() {
stop()
nc.Drain() //nolint:errcheck
}
}

// getEnv returns the environment variable value or a fallback default.
func getEnv(key, fallback string) string {
if v, ok := os.LookupEnv(key); ok {
return v
}
return fallback
}
