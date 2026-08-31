package main

import (
	"cmp"
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/robertlestak/cert-manager-sync/internal/metrics"
	"github.com/robertlestak/cert-manager-sync/pkg/certmanagersync"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
	log "github.com/sirupsen/logrus"
	_ "golang.org/x/crypto/x509roots/fallback" // Embeds x509root certificates into the binary
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
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

// runController starts the secret informer and blocks until ctx is cancelled.
//
// Under leader election this is the OnStartedLeading callback, and ctx is
// cancelled the moment leadership is lost — so a demoted replica stops
// reconciling rather than racing the new leader.
func runController(ctx context.Context) {
	l := log.WithFields(
		log.Fields{
			"fn": "runController",
		},
	)
	l.Info("starting secret informer")
	factory := informers.NewSharedInformerFactory(state.KubeClient, 30*time.Second)
	secretInformer := factory.Core().V1().Secrets().Informer()

	if _, err := secretInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			s, ok := obj.(*v1.Secret)
			if !ok {
				return
			}
			reconcileSecret(l, s)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			s, ok := newObj.(*v1.Secret)
			if !ok {
				return
			}
			reconcileSecret(l, s)
		},
	}); err != nil {
		l.WithError(err).Fatal("failed to register secret event handler")
	}

	factory.Start(ctx.Done())

	// Wait for the caches to sync
	if !cache.WaitForCacheSync(ctx.Done(), secretInformer.HasSynced) {
		l.Error("timed out waiting for caches to sync")
		return
	}

	// Run the informer
	<-ctx.Done()
	l.Info("stopping secret informer")
}

func main() {
	l := log.WithFields(
		log.Fields{
			"fn": "main",
		},
	)
	l.Info("starting cert-manager-sync")
	if os.Getenv("ENABLE_METRICS") != "false" {
		// Metrics serve from every replica, leader or not, so scrape targets
		// and probes do not flap on failover.
		go metrics.Serve()
	}

	// SIGTERM must reach the leader elector, not just the process: with
	// ReleaseOnCancel it hands the lease back immediately, so a rolling
	// restart does not pause syncing for a full lease duration.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if !leaderElectionEnabled() {
		l.Warn("leader election disabled; run a single replica to avoid duplicate remote certificates")
		runController(ctx)
		return
	}

	// An environment that cannot support election does not end up here: it is
	// degraded to running unelected inside runWithLeaderElection, so a missing
	// Lease grant never costs certificate syncing. What reaches this branch is
	// a lost lease, or LEADER_ELECTION_REQUIRED with no way to satisfy it.
	if err := runWithLeaderElection(ctx, runController); err != nil {
		// Exit non-zero so the pod restarts and re-contends rather than
		// lingering as a healthy-looking replica that syncs nothing.
		l.WithError(err).Error("leader election ended")
		os.Exit(1)
	}
}

// Function-typed indirection so reconcileSecret can be exercised without
// reaching into the real Kubernetes client or store implementations.
var (
	handleSecretFn       = certmanagersync.HandleSecret
	handleSecretDeleteFn = certmanagersync.HandleSecretDelete
	ensureFinalizerFn    = certmanagersync.EnsureFinalizer
	removeFinalizerFn    = certmanagersync.RemoveFinalizer
)

// reconcileSecret routes a secret event to the right handler based on its
// deletion timestamp, finalizer state, and effective delete policy.
//
// Order matters:
//  1. If the secret is pending deletion AND carries our finalizer, drive
//     HandleSecretDelete — even if the secret is no longer "watched" (data
//     may already be cleared).
//  2. Otherwise, only watched secrets get any further work.
//  3. For watched secrets with a delete-policy of "delete", ensure the
//     finalizer is in place before syncing so a subsequent deletion is caught.
//  4. For watched secrets that have switched away from "delete", drop the
//     finalizer so the user is not left with a stuck secret.
//  5. Run the normal HandleSecret sync path.
func reconcileSecret(l *log.Entry, s *v1.Secret) {
	ctx := context.Background()

	if state.SecretDeletePending(s) {
		if err := handleSecretDeleteFn(s); err != nil {
			l.WithError(err).WithFields(log.Fields{
				"namespace": s.Namespace,
				"name":      s.Name,
			}).Error("delete reconcile error")
		}
		return
	}

	if !state.SecretWatched(s) {
		// The secret may have lost its sync-enabled annotation while still
		// carrying our finalizer; drop the finalizer so the user is not stuck.
		if state.HasFinalizer(s) && s.DeletionTimestamp == nil {
			if _, err := removeFinalizerFn(ctx, s); err != nil {
				l.WithError(err).Error("failed to remove finalizer from no-longer-watched secret")
			}
		}
		return
	}

	if state.EffectiveDeletePolicy(s) == state.DeletePolicyDelete {
		if _, err := ensureFinalizerFn(ctx, s); err != nil {
			l.WithError(err).WithFields(log.Fields{
				"namespace": s.Namespace,
				"name":      s.Name,
			}).Error("failed to ensure delete finalizer")
			// Don't return — still attempt the sync.
		}
	} else if state.HasFinalizer(s) {
		// Policy flipped from delete -> retain; drop the finalizer.
		if _, err := removeFinalizerFn(ctx, s); err != nil {
			l.WithError(err).Error("failed to remove finalizer after policy change")
		}
	}

	if err := handleSecretFn(s); err != nil {
		l.Error(err)
	}
}
