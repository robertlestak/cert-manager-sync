package metrics

import (
	"net/http"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

var (
	SyncStatus = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cert_manager_sync_status",
		Help: "cert-manager-sync status by namespace, secret, and store",
	}, []string{"namespace", "secret", "store", "status"})
)

func InitMetrics() {
	prometheus.MustRegister(SyncStatus)
}

func SetSuccess(namespace, secret, store string) {
	SyncStatus.WithLabelValues(namespace, secret, store, "success").Set(1)
}

func SetFailure(namespace, secret, store string) {
	SyncStatus.WithLabelValues(namespace, secret, store, "fail").Set(1)
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
