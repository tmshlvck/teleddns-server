// Package metrics holds the Prometheus instrumentation for teleddns-server
// (PRD §11.5). Counters/histograms are package-level instruments incremented at
// the DDNS handler, the auth paths and the sync worker; the DB-derived gauges
// (zones, records, pending pushes) are produced per-scrape by a collector wired
// via RegisterStats. Metrics are deliberately not labelled by user/token — the
// structured audit log carries the actor; here we keep cardinality bounded.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// reg is a private registry so /metrics exposes only our series (not the
// default process/Go collectors, which would leak host details on a public
// deployment).
var reg = prometheus.NewRegistry()

var (
	// DDNSUpdates counts every DDNS outcome. Abuse alerting keys off its rate.
	DDNSUpdates = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "teleddns_ddns_updates_total",
		Help: "DDNS update outcomes by dyndns2 result.",
	}, []string{"result"})

	// AuthFailures counts rejected authentications across all surfaces.
	AuthFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "teleddns_auth_failures_total",
		Help: "Authentication failures by surface and reason.",
	}, []string{"surface", "reason"})

	// RateLimited counts requests rejected by a rate limit (HTTP 429).
	RateLimited = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "teleddns_ratelimited_total",
		Help: "Requests rejected by rate limiting, by surface.",
	}, []string{"surface"})

	// BackendPushSeconds times backend push attempts.
	BackendPushSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "teleddns_backend_push_seconds",
		Help:    "Backend push duration in seconds, by kind.",
		Buckets: prometheus.DefBuckets,
	}, []string{"kind"})

	// BackendPushTotal counts backend push attempts by outcome.
	BackendPushTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "teleddns_backend_push_total",
		Help: "Backend push attempts by kind and result.",
	}, []string{"kind", "result"})

	// WorkerLastTick is the unix timestamp of the last sync-worker tick; a
	// stalled value (vs now) means the worker died or wedged.
	WorkerLastTick = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "teleddns_worker_last_tick_seconds",
		Help: "Unix timestamp of the last sync-worker tick.",
	})

	// KnotUp is 1 if the last knotc status probe succeeded, else 0 (1 for the
	// log backend, which has no daemon to probe).
	KnotUp = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "teleddns_knot_up",
		Help: "1 if the last knotc status probe succeeded, else 0.",
	})
)

func init() {
	reg.MustRegister(DDNSUpdates, AuthFailures, RateLimited,
		BackendPushSeconds, BackendPushTotal, WorkerLastTick, KnotUp)

	// Pre-instantiate the common label sets to 0 so dashboards/alerts have a
	// series before the first event.
	for _, r := range []string{"good", "nochg", "nohost", "notyours", "badauth", "notfqdn", "abuse", "error"} {
		DDNSUpdates.WithLabelValues(r)
	}
	for _, kind := range []string{"zone", "zone-remove"} {
		for _, res := range []string{"success", "error"} {
			BackendPushTotal.WithLabelValues(kind, res)
		}
	}
}

// Snapshot carries the DB-derived gauge values produced on each scrape.
type Snapshot struct {
	Zones          float64
	RecordsByType  map[string]float64 // RR type name → count
	PendingByState map[string]float64 // sync-task state → count
}

var (
	zonesDesc         = prometheus.NewDesc("teleddns_zones", "Number of zones.", nil, nil)
	recordsDesc       = prometheus.NewDesc("teleddns_records", "Total resource records across all zones.", nil, nil)
	recordsByTypeDesc = prometheus.NewDesc("teleddns_records_by_type", "Resource records by RR type.", []string{"type"}, nil)
	pendingDesc       = prometheus.NewDesc("teleddns_pending_pushes", "Sync tasks by state.", []string{"state"}, nil)
)

type statsCollector struct{ fn func() Snapshot }

func (c statsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- zonesDesc
	ch <- recordsDesc
	ch <- recordsByTypeDesc
	ch <- pendingDesc
}

func (c statsCollector) Collect(ch chan<- prometheus.Metric) {
	s := c.fn()
	ch <- prometheus.MustNewConstMetric(zonesDesc, prometheus.GaugeValue, s.Zones)
	var total float64
	for t, n := range s.RecordsByType {
		ch <- prometheus.MustNewConstMetric(recordsByTypeDesc, prometheus.GaugeValue, n, t)
		total += n
	}
	ch <- prometheus.MustNewConstMetric(recordsDesc, prometheus.GaugeValue, total)
	for st, n := range s.PendingByState {
		ch <- prometheus.MustNewConstMetric(pendingDesc, prometheus.GaugeValue, n, st)
	}
}

// RegisterStats wires the per-scrape DB gauge collector. Call once at startup.
func RegisterStats(fn func() Snapshot) {
	reg.MustRegister(statsCollector{fn: fn})
}

// Handler returns the /metrics HTTP handler bound to the private registry.
func Handler() http.Handler {
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
}
