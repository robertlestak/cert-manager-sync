package metrics

import (
	"fmt"
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

func init() {
	InitMetrics()
}

func Serve(port int, path string) {
	l := log.WithFields(log.Fields{
		"pkg":  "metrics",
		"fn":   "Serve",
		"port": port,
		"path": path,
	})
	l.Info("starting metrics server")
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	http.Handle(path, promhttp.Handler())
	if err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil); err != nil {
		l.WithError(err).Error("error starting http server")
		os.Exit(1)
	}
}
