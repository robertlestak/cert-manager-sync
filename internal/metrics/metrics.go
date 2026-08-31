package metrics

import (
	"cmp"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

var (
	SyncStatus = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cert_manager_sync_status",
		Help: "cert-manager-sync status by namespace, secret, and store",
	}, []string{"namespace", "secret", "store", "status"})

	// LeaderElectionDegraded is 1 when leader election was asked for but the
	// environment cannot support it (no coordination.k8s.io Lease RBAC in the
	// pod's namespace), so this replica reconciles unelected. Harmless at one
	// replica; above one it is the duplicate-remote-certificate bug. Alert on
	// it rather than discovering it in the provider's console.
	LeaderElectionDegraded = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "cert_manager_sync_leader_election_degraded",
		Help: "1 when leader election was requested but is unavailable and the replica reconciles unelected",
	})
)

func InitMetrics() {
	prometheus.MustRegister(SyncStatus)
	prometheus.MustRegister(LeaderElectionDegraded)
}

func SetSuccess(namespace, secret, store string) {
	SyncStatus.WithLabelValues(namespace, secret, store, "success").Set(1)
}

func SetFailure(namespace, secret, store string) {
	SyncStatus.WithLabelValues(namespace, secret, store, "fail").Set(1)
}

func SetLeaderElectionDegraded(degraded bool) {
	if degraded {
		LeaderElectionDegraded.Set(1)
		return
	}
	LeaderElectionDegraded.Set(0)
}

func init() {
	InitMetrics()
}

func Serve() {
	l := log.WithFields(log.Fields{
		"pkg": "metrics",
		"fn":  "Serve",
	})
	l.Debug("starting metrics server")
	port := cmp.Or(os.Getenv("METRICS_PORT"), "9090")
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	http.Handle("/metrics", promhttp.Handler())
	// Explicit timeouts: the default http.Server has none, so a client that
	// opens a connection and never finishes its request holds a goroutine and
	// an fd indefinitely. This listener is reachable from anything that can
	// reach the pod.
	srv := &http.Server{
		Addr:              ":" + port,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		l.WithError(err).Error("error starting http server")
		os.Exit(1)
	}
}
