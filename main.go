// Package main is the entry point for the OpenGuard v5 platform.
package main

import (
"context"
"os"
"os/signal"
"syscall"
"time"

"go.opentelemetry.io/otel"
"go.opentelemetry.io/otel/sdk/trace"
"go.uber.org/zap"

consoleapi "github.com/DiniMuhd7/openguard/services/console-api"
auditled "github.com/DiniMuhd7/openguard/services/audit-ledger"
"github.com/DiniMuhd7/openguard/services/detect"
"github.com/DiniMuhd7/openguard/services/ingest"
orchestrator "github.com/DiniMuhd7/openguard/services/response-orchestrator"
policyengine "github.com/DiniMuhd7/openguard/services/policy-engine"
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

func main() {
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

// Initialize ingest service.
ingestSvc, err := ingest.NewService(ingest.Config{
NATSUrl:  natsURL,
SchemaPath: getEnv("SCHEMA_PATH", "./schemas/unified-event.schema.json"),
}, detectSvc, orch, logger)
if err != nil {
logger.Fatal("failed to initialize ingest service", zap.Error(err))
}

// Initialize console API.
apiServer := consoleapi.NewServer(consoleapi.Config{
ListenAddr: listenAddr,
JWTSecret:  getEnv("JWT_SECRET", "change-me-in-production"),
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

// getEnv returns the environment variable value or a fallback default.
func getEnv(key, fallback string) string {
if v, ok := os.LookupEnv(key); ok {
return v
}
return fallback
}
