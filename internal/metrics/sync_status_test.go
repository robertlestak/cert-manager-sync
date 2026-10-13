package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestSyncStatusTransitions(t *testing.T) {
	for _, outcomes := range [][]string{
		{"fail", "success", "success", "fail", "fail", "success"},
		{"success", "fail", "success"},
	} {
		t.Run(outcomes[0]+"_first", func(t *testing.T) {
			namespace, secret, store := "metrics-tests", t.Name(), "gcp"
			cleanupSyncStatus(t, namespace, secret, store)

			for _, outcome := range outcomes {
				if outcome == "success" {
					SetSuccess(namespace, secret, store)
					assertSyncStatus(t, namespace, secret, store, 1, 0)
				} else {
					SetFailure(namespace, secret, store)
					assertSyncStatus(t, namespace, secret, store, 0, 1)
				}
			}
		})
	}
}

func TestSyncStatusLabelsIsolation(t *testing.T) {
	// Recovering one certificate/store must not clear another one's failure.
	labels := [][3]string{
		{"metrics-tests", t.Name(), "gcp"},
		{"metrics-tests", t.Name(), "acm"},
		{"other-namespace", t.Name(), "gcp"},
		{"metrics-tests", t.Name() + "-other-secret", "gcp"},
	}
	for _, label := range labels {
		cleanupSyncStatus(t, label[0], label[1], label[2])
		SetFailure(label[0], label[1], label[2])
	}

	SetSuccess(labels[0][0], labels[0][1], labels[0][2])
	assertSyncStatus(t, labels[0][0], labels[0][1], labels[0][2], 1, 0)
	for _, label := range labels[1:] {
		assertSyncStatus(t, label[0], label[1], label[2], 0, 1)
	}
}

func assertSyncStatus(t *testing.T, namespace, secret, store string, success, failure float64) {
	t.Helper()
	registry := prometheus.NewRegistry()
	registry.MustRegister(SyncStatus)
	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("gather sync metrics: %v", err)
	}
	wanted := map[string]float64{"success": success, "fail": failure}
	seen := make(map[string]bool)
	for _, family := range families {
		for _, metric := range family.GetMetric() {
			labels := make(map[string]string)
			for _, label := range metric.GetLabel() {
				labels[label.GetName()] = label.GetValue()
			}
			if labels["namespace"] != namespace || labels["secret"] != secret || labels["store"] != store {
				continue
			}
			status := labels["status"]
			seen[status] = true
			if got := metric.GetGauge().GetValue(); got != wanted[status] {
				t.Errorf("%s/%s store %s status %s = %v, want %v", namespace, secret, store, status, got, wanted[status])
			}
		}
	}
	for status := range wanted {
		if !seen[status] {
			t.Errorf("%s/%s store %s is missing status %s", namespace, secret, store, status)
		}
	}
}

func cleanupSyncStatus(t *testing.T, namespace, secret, store string) {
	t.Helper()
	t.Cleanup(func() {
		SyncStatus.DeleteLabelValues(namespace, secret, store, "success")
		SyncStatus.DeleteLabelValues(namespace, secret, store, "fail")
	})
}
