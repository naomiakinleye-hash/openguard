// Package baseline implements per-entity exponential weighted moving average
// (EWMA) behavioural baseline tracking for OpenGuard v5.
//
// The engine tracks per-(entity, metric) EWMA mean and variance, and flags
// observations that deviate more than 3 standard deviations from the baseline
// (the 3-sigma / 99.7% rule).  No external ML dependencies are required; the
// algorithm is purely statistical.
package baseline

import (
	"math"
	"sync"
	"time"
)

// Engine tracks behavioural baselines for an arbitrary number of entities.
type Engine struct {
	mu       sync.RWMutex
	entities map[string]*entityBaseline
	alpha    float64 // EWMA smoothing factor (0 < alpha ≤ 1; smaller = smoother)
}

// entityBaseline holds the EWMA state for one (entity, metric) pair.
type entityBaseline struct {
	Mean        float64
	Variance    float64
	SampleCount int
	LastUpdate  time.Time
}

// NewEngine creates a baseline Engine with the given EWMA alpha.
// alpha=0.1 is appropriate for slow-moving security metrics.
func NewEngine(alpha float64) *Engine {
	if alpha <= 0 || alpha > 1 {
		alpha = 0.1
	}
	return &Engine{
		entities: make(map[string]*entityBaseline),
		alpha:    alpha,
	}
}

// Record updates the EWMA baseline for (entityType, entityID, metric).
// Call this every time a metric observation arrives.
func (e *Engine) Record(entityType, entityID, metric string, value float64) {
	key := entityType + ":" + entityID + ":" + metric
	e.mu.Lock()
	defer e.mu.Unlock()

	b, exists := e.entities[key]
	if !exists {
		e.entities[key] = &entityBaseline{
			Mean:        value,
			Variance:    0,
			SampleCount: 1,
			LastUpdate:  time.Now(),
		}
		return
	}
	// Welford-EWMA update: numerically stable incremental mean+variance.
	diff := value - b.Mean
	b.Mean += e.alpha * diff
	b.Variance = (1 - e.alpha) * (b.Variance + e.alpha*diff*diff)
	b.SampleCount++
	b.LastUpdate = time.Now()
}

// IsAnomaly checks whether value is anomalous relative to the entity's baseline.
// Returns (anomalous, zScore, baselineMean).
// Returns (false, 0, value) when fewer than minSamples observations exist.
func (e *Engine) IsAnomaly(entityType, entityID, metric string, value float64) (bool, float64, float64) {
	const minSamples = 10
	const sigmaThreshold = 3.0

	key := entityType + ":" + entityID + ":" + metric
	e.mu.RLock()
	defer e.mu.RUnlock()

	b, exists := e.entities[key]
	if !exists || b.SampleCount < minSamples {
		return false, 0, value
	}

	stdDev := math.Sqrt(b.Variance)
	if stdDev < 1e-9 {
		// Zero variance — any non-negligible deviation is anomalous.
		if math.Abs(value-b.Mean) > 0.01 {
			return true, 100.0, b.Mean
		}
		return false, 0, b.Mean
	}

	zScore := (value - b.Mean) / stdDev
	return math.Abs(zScore) > sigmaThreshold, zScore, b.Mean
}

// DriftScore returns a 0–25 anomaly contribution score for a metric observation.
// Designed to plug directly into the detect service's RiskComponents.AnomalyScore.
func (e *Engine) DriftScore(entityType, entityID, metric string, value float64) float64 {
	anomalous, zScore, _ := e.IsAnomaly(entityType, entityID, metric, value)
	if !anomalous {
		return 0
	}
	// Scale z-score to 0–25: z=3 → 5, z=6 → 15, z≥10 → 25.
	scaled := math.Min(math.Abs(zScore)/10.0*25.0, 25.0)
	return scaled
}

// EntityStats is a snapshot of one entity's baseline for monitoring.
type EntityStats struct {
	Key         string    `json:"key"`
	Mean        float64   `json:"mean"`
	StdDev      float64   `json:"std_dev"`
	SampleCount int       `json:"sample_count"`
	LastUpdate  time.Time `json:"last_update"`
}

// Stats returns a snapshot of all entity baselines.
func (e *Engine) Stats() []EntityStats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]EntityStats, 0, len(e.entities))
	for key, b := range e.entities {
		out = append(out, EntityStats{
			Key:         key,
			Mean:        b.Mean,
			StdDev:      math.Sqrt(b.Variance),
			SampleCount: b.SampleCount,
			LastUpdate:  b.LastUpdate,
		})
	}
	return out
}
