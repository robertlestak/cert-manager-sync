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

func main() {
	l := log.WithFields(
		log.Fields{
			"fn": "main",
		},
	)
	l.Info("starting cert-manager-sync")
	if os.Getenv("ENABLE_METRICS") != "false" {
		go metrics.Serve()
	}
	factory := informers.NewSharedInformerFactory(state.KubeClient, 30*time.Second)
	secretInformer := factory.Core().V1().Secrets().Informer()

	stopper := make(chan struct{})
	defer close(stopper)

	secretInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
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
	})

	factory.Start(stopper)

	// Wait for the caches to sync
	if !cache.WaitForCacheSync(stopper, secretInformer.HasSynced) {
		panic("Timed out waiting for caches to sync")
	}

	// Run the informer
	<-stopper
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
