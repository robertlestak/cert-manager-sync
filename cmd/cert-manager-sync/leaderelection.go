package main

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
	log "github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

// Leader election exists because the operator's remote writes are not
// idempotent for every store. Two replicas that each observe the same secret
// before either has written back its remote id (acm-certificate-arn.N,
// cloudflare-cert-id, ...) both take the store's *create* path, so each
// renewal mints N duplicate remote certificates and one replica's write-back
// wins — orphaning the others. For ACM that burns the account's rolling
// 365-day import quota. See issue #48.
//
// Only the leader runs the informer. Non-leaders stay up and keep serving
// metrics so probes and scrape targets do not flap on failover.

const (
	defaultLockName      = "cert-manager-sync-leader"
	defaultLeaseDuration = 15 * time.Second
	defaultRenewDeadline = 10 * time.Second
	defaultRetryPeriod   = 2 * time.Second

	// serviceAccountNamespaceFile is where the kubelet projects the pod's
	// namespace when the downward API is not wired up explicitly.
	serviceAccountNamespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

// leaderElectionEnabled reports whether leader election is active. It is on by
// default: the failure mode it prevents (duplicate remote certificates) is
// silent, expensive, and only visible in the provider's console.
func leaderElectionEnabled() bool {
	return !strings.EqualFold(os.Getenv("LEADER_ELECTION_ENABLED"), "false")
}

// leaderElectionNamespace resolves the namespace holding the Lease, in
// descending order of explicitness: operator config, downward API, the
// projected service account token's namespace file.
func leaderElectionNamespace() (string, error) {
	if ns := os.Getenv("LEADER_ELECTION_NAMESPACE"); ns != "" {
		return ns, nil
	}
	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		return ns, nil
	}
	b, err := os.ReadFile(serviceAccountNamespaceFile)
	if err == nil {
		if ns := strings.TrimSpace(string(b)); ns != "" {
			return ns, nil
		}
	}
	return "", fmt.Errorf("cannot determine the namespace for the leader election Lease: set LEADER_ELECTION_NAMESPACE (or POD_NAMESPACE via the downward API), or set LEADER_ELECTION_ENABLED=false")
}

// leaderElectionIdentity returns this candidate's lock identity. The pod name
// alone is not sufficient: a StatefulSet-style pod that restarts reuses its
// name, and a stale record from the previous incarnation would let the new
// process believe it already holds the lease. The uuid suffix makes every
// process distinct.
func leaderElectionIdentity() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "cert-manager-sync"
	}
	return cmp.Or(os.Getenv("POD_NAME"), host) + "_" + uuid.New().String()
}

// leaderElectionTimings returns the lease/renew/retry durations, honoring the
// LEADER_ELECTION_{LEASE_DURATION,RENEW_DEADLINE,RETRY_PERIOD} overrides.
//
// client-go panics on an inconsistent set (it requires
// leaseDuration > renewDeadline > retryPeriod*JitterFactor), so an override
// that would not survive that check is rejected here and the defaults are used.
// A misconfigured duration should not take the operator down.
func leaderElectionTimings() (lease, renew, retry time.Duration) {
	l := log.WithFields(log.Fields{"fn": "leaderElectionTimings"})
	lease = envDuration("LEADER_ELECTION_LEASE_DURATION", defaultLeaseDuration)
	renew = envDuration("LEADER_ELECTION_RENEW_DEADLINE", defaultRenewDeadline)
	retry = envDuration("LEADER_ELECTION_RETRY_PERIOD", defaultRetryPeriod)
	// Mirror the invariants client-go asserts in NewLeaderElector.
	if lease <= renew || renew <= time.Duration(float64(retry)*leaderelection.JitterFactor) || lease < 1 || renew < 1 || retry < 1 {
		l.WithFields(log.Fields{
			"leaseDuration": lease,
			"renewDeadline": renew,
			"retryPeriod":   retry,
		}).Error("invalid leader election timings; falling back to defaults")
		return defaultLeaseDuration, defaultRenewDeadline, defaultRetryPeriod
	}
	return lease, renew, retry
}

func envDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.WithError(err).WithField("key", key).Error("invalid duration; using default")
		return def
	}
	return d
}

// checkLeasePermissions fails fast when the operator cannot read the Lease it
// is about to contend for.
//
// Without this, a missing RBAC rule is nearly invisible: leaderelection retries
// the Forbidden response forever at retryPeriod, OnStartedLeading never fires,
// and the operator sits there healthy-looking while syncing nothing. Crashing
// with an actionable message is far kinder than a silent no-op.
func checkLeasePermissions(ctx context.Context, namespace, name string) error {
	_, err := state.KubeClient.CoordinationV1().Leases(namespace).Get(ctx, name, metav1.GetOptions{})
	if err == nil || apierrors.IsNotFound(err) {
		// Not found is the expected state before the first election.
		return nil
	}
	if apierrors.IsForbidden(err) {
		return fmt.Errorf("no permission to read Lease %s/%s: grant get/create/update on coordination.k8s.io leases in that namespace, or set LEADER_ELECTION_ENABLED=false to run a single replica without election: %w", namespace, name, err)
	}
	return fmt.Errorf("failed to read Lease %s/%s: %w", namespace, name, err)
}

// runWithLeaderElection blocks, running run() only while this process holds the
// lease. It returns when ctx is cancelled or when leadership is lost.
func runWithLeaderElection(ctx context.Context, run func(context.Context)) error {
	l := log.WithFields(log.Fields{"fn": "runWithLeaderElection"})

	namespace, err := leaderElectionNamespace()
	if err != nil {
		return err
	}
	lockName := cmp.Or(os.Getenv("LEADER_ELECTION_LOCK_NAME"), defaultLockName)
	identity := leaderElectionIdentity()
	lease, renew, retry := leaderElectionTimings()

	if err := checkLeasePermissions(ctx, namespace, lockName); err != nil {
		return err
	}

	l.WithFields(log.Fields{
		"namespace":     namespace,
		"lock":          lockName,
		"identity":      identity,
		"leaseDuration": lease,
		"renewDeadline": renew,
		"retryPeriod":   retry,
	}).Info("contending for leadership")

	lock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{Name: lockName, Namespace: namespace},
		Client:    state.KubeClient.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity:      identity,
			EventRecorder: state.EventRecorder,
		},
	}

	// lostLeadership distinguishes "we were demoted" from "we were asked to
	// shut down"; the caller turns the former into a non-zero exit so the pod
	// restarts and re-contends from a clean slate.
	lostLeadership := false

	leaderelection.RunOrDie(ctx, leaderelection.LeaderElectionConfig{
		Lock: lock,
		// Hand the lease back on SIGTERM instead of making the next leader wait
		// out the full lease duration. This is what keeps a rolling restart
		// from pausing syncs for ~15s.
		ReleaseOnCancel: true,
		LeaseDuration:   lease,
		RenewDeadline:   renew,
		RetryPeriod:     retry,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: run,
			OnStoppedLeading: func() {
				if ctx.Err() != nil {
					l.Info("released leadership on shutdown")
					return
				}
				lostLeadership = true
				l.Error("lost leadership")
			},
			OnNewLeader: func(current string) {
				if current == identity {
					return
				}
				l.WithField("leader", current).Info("observing another leader")
			},
		},
	})

	if lostLeadership {
		return fmt.Errorf("lost leadership")
	}
	return nil
}
