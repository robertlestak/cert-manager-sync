package metrics

import (
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestInitMetrics(t *testing.T) {
	// Reset the global registry to ensure a clean state
	prometheus.DefaultRegisterer = prometheus.NewRegistry()

	InitMetrics()

	// Check if SyncStatus is registered
	metricFamilies, err := prometheus.DefaultGatherer.Gather()
	assert.NoError(t, err)
	// ensure we have at least one metric family
	assert.Greater(t, len(metricFamilies), 0)
	// ensure the metric family is the one we expect
	for _, mf := range metricFamilies {
		if *mf.Name == "cert_manager_sync_status" {
			return
		}
	}
}

func TestServe(t *testing.T) {
	// Mock environment variable
	os.Setenv("METRICS_PORT", "9091")

	// Mock log output to prevent actual logging during tests
	logrus.SetOutput(os.Stdout)
	logrus.SetLevel(logrus.PanicLevel)

	// Start the metrics server in a separate goroutine
	go Serve()

	// Wait a moment for the server to start
	time.Sleep(100 * time.Millisecond)

	// Test /healthz endpoint
	resp, err := http.Get("http://localhost:9091/healthz")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Test /metrics endpoint
	resp, err = http.Get("http://localhost:9091/metrics")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Cleanup: reset the environment variable
	os.Unsetenv("METRICS_PORT")
}
