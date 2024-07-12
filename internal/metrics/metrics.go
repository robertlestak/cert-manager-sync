package metrics

import (
	"net/http"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

var (
	SyncSuccess = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "cert_manager_sync_success",
		Help: "cert-manager-sync successes by namespace, secret, and store",
	}, []string{"namespace", "secret", "store"})
	SyncFailure = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "cert_manager_sync_failure",
		Help: "cert-manager-sync failures by namespace, secret, and store",
	}, []string{"namespace", "secret", "store"})
)

func InitMetrics() {
	prometheus.MustRegister(SyncSuccess)
	prometheus.MustRegister(SyncFailure)
}

func SetSuccess(namespace, secret, store string) {
	SyncSuccess.WithLabelValues(namespace, secret, store).Inc()
}

func SetFailure(namespace, secret, store string) {
	SyncFailure.WithLabelValues(namespace, secret, store).Inc()
}

func Serve() {
	l := log.WithFields(log.Fields{
		"pkg": "metrics",
		"fn":  "Serve",
	})
	l.Debug("starting metrics server")
	InitMetrics()
	port := os.Getenv("METRICS_PORT")
	if port == "" {
		port = "9090"
	}
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	http.Handle("/metrics", promhttp.Handler())
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		l.WithError(err).Error("error starting http server")
		os.Exit(1)
	}
}
