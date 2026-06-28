package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func scrape(t *testing.T) string {
	t.Helper()
	rr := httptest.NewRecorder()
	Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("metrics scrape status = %d", rr.Code)
	}
	return rr.Body.String()
}

func TestCountersExposedAndIncrement(t *testing.T) {
	// Pre-initialized label sets exist at 0 before any event.
	out := scrape(t)
	if !strings.Contains(out, `teleddns_ddns_updates_total{result="good"} 0`) {
		t.Fatalf("expected good counter pre-initialized to 0:\n%s", out)
	}

	DDNSUpdates.WithLabelValues("good").Inc()
	DDNSUpdates.WithLabelValues("good").Inc()
	AuthFailures.WithLabelValues("ddns", "bad_password").Inc()
	RateLimited.WithLabelValues("ddns").Inc()

	out = scrape(t)
	for _, want := range []string{
		`teleddns_ddns_updates_total{result="good"} 2`,
		`teleddns_auth_failures_total{reason="bad_password",surface="ddns"} 1`, // labels sorted alphabetically
		`teleddns_ratelimited_total{surface="ddns"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestStatsCollector(t *testing.T) {
	RegisterStats(func() Snapshot {
		return Snapshot{
			Zones:          3,
			RecordsByType:  map[string]float64{"A": 5, "AAAA": 2},
			PendingByState: map[string]float64{"pending": 1, "in_flight": 0, "failed": 0},
		}
	})

	out := scrape(t)
	for _, want := range []string{
		"teleddns_zones 3",
		"teleddns_records 7", // sum across types
		`teleddns_records_by_type{type="A"} 5`,
		`teleddns_pending_pushes{state="pending"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}
