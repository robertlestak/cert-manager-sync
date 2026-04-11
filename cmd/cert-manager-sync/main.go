package main

import (
	"cmp"
	"context"
	"os"
	"time"

	"github.com/robertlestak/cert-manager-sync/internal/metrics"
	"github.com/robertlestak/cert-manager-sync/pkg/certmanagersync"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
	log "github.com/sirupsen/logrus"
	_ "golang.org/x/crypto/x509roots/fallback" // Embeds x509root certificates into the binary
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

func init() {
	ll, lerr := log.ParseLevel(cmp.Or(os.Getenv("LOG_LEVEL"), "info"))
	if lerr != nil {
		ll = log.InfoLevel
	}
	log.SetLevel(ll)
	if os.Getenv("LOG_FORMAT") == "json" {
		log.SetFormatter(&log.JSONFormatter{})
	}
	l := log.WithFields(
		log.Fields{
			"action": "init",
		},
	)
	state.OperatorName = cmp.Or(os.Getenv("OPERATOR_NAME"), state.OperatorName)
	cerr := state.CreateKubeClient()
	if cerr != nil {
		l.Fatal(cerr)
	}
}

func runController(ctx context.Context) {
	l := log.WithFields(log.Fields{"fn": "runController"})
	l.Info("starting informers as leader")

	factory := informers.NewSharedInformerFactory(state.KubeClient, 30*time.Second)
	secretInformer := factory.Core().V1().Secrets().Informer()

	secretInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			s := obj.(*v1.Secret)
			if !state.SecretWatched(s) {
				return
			}
			if err := certmanagersync.HandleSecret(s); err != nil {
				l.Error(err)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			s := newObj.(*v1.Secret)
			if !state.SecretWatched(s) {
				return
			}
			if err := certmanagersync.HandleSecret(s); err != nil {
				l.Error(err)
			}
		},
	})

	factory.Start(ctx.Done())

	if !cache.WaitForCacheSync(ctx.Done(), secretInformer.HasSynced) {
		l.Error("timed out waiting for caches to sync")
		return
	}

	<-ctx.Done()
	l.Info("leader lost, stopping informers")
}

func main() {
	l := log.WithFields(log.Fields{"fn": "main"})
	l.Info("starting cert-manager-sync")

	if os.Getenv("ENABLE_METRICS") != "false" {
		go metrics.Serve()
	}

	if os.Getenv("LEADER_ELECTION_ENABLED") == "false" {
		l.Info("leader election disabled, running directly")
		runController(context.Background())
		return
	}

	id, _ := os.Hostname()
	ns := cmp.Or(os.Getenv("LEADER_ELECTION_NAMESPACE"), "cert-manager-sync")
	lockName := cmp.Or(os.Getenv("LEADER_ELECTION_LOCK_NAME"), "cert-manager-sync-leader")

	lock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{Name: lockName, Namespace: ns},
		Client:    state.KubeClient.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: id,
		},
	}

	ctx := context.Background()

	leaderelection.RunOrDie(ctx, leaderelection.LeaderElectionConfig{
		Lock:            lock,
		ReleaseOnCancel: true,
		LeaseDuration:   15 * time.Second,
		RenewDeadline:   10 * time.Second,
		RetryPeriod:     2 * time.Second,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: runController,
			OnStoppedLeading: func() {
				l.Info("leader election lost")
			},
			OnNewLeader: func(identity string) {
				if identity == id {
					return
				}
				l.Infof("new leader elected: %s", identity)
			},
		},
	})
}
