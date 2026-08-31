package main

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/robertlestak/cert-manager-sync/internal/metrics"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
	log "github.com/sirupsen/logrus"
	authorizationv1 "k8s.io/api/authorization/v1"
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
//
// Election is gated on the environment being able to support it. The Lease
// RBAC is new in 1.6.0, so an install that upgrades before its RBAC does would
// otherwise crash-loop on a permission it never needed at one replica. A
// process that cannot elect logs loudly, raises
// cert_manager_sync_leader_election_degraded, and reconciles unelected —
// unless LEADER_ELECTION_REQUIRED is set, which the chart does above one
// replica, where unelected is not degraded but wrong.

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

// leaderElectionRequired reports whether an environment that cannot support
// leader election should be treated as fatal rather than degraded.
//
// Off by default, because a single replica that cannot hold a Lease is still
// correct — it is the only writer either way, and refusing to start would take
// certificate syncing down over a permission it does not need. Set it for
// replicaCount > 1, where running unelected is not a degraded mode but the
// duplicate-remote-certificate bug this feature exists to prevent; the chart
// sets it automatically. See issue #48.
func leaderElectionRequired() bool {
	return strings.EqualFold(os.Getenv("LEADER_ELECTION_REQUIRED"), "true")
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

// leaseVerbs are what resourcelock.LeaseLock exercises over the lock's
// lifetime. A candidate that can Get but not Update acquires nothing and
// renews nothing, so all three have to be checked together.
var leaseVerbs = []string{"get", "create", "update"}

// checkLeaseCapability reports whether this environment can support leader
// election, returning a descriptive error when it cannot.
//
// This is a capability probe, not a health check. Leader election is a
// cluster-side capability — it needs coordination.k8s.io Lease RBAC in the
// pod's namespace — and an operator that was syncing certificates fine before
// the feature existed must not stop syncing them because that RBAC has not
// been applied yet. The caller degrades to running unelected (see
// runWithLeaderElection) unless LEADER_ELECTION_REQUIRED says otherwise.
//
// SelfSubjectAccessReview asks the API server the question directly, and
// covers create/update, which cannot be probed without actually writing. If
// the review itself is unavailable, fall back to reading the Lease: it still
// catches the common case of no rule at all.
func checkLeaseCapability(ctx context.Context, namespace, name string) error {
	for _, verb := range leaseVerbs {
		review := &authorizationv1.SelfSubjectAccessReview{
			Spec: authorizationv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: namespace,
					Group:     "coordination.k8s.io",
					Resource:  "leases",
					Name:      name,
					Verb:      verb,
				},
			},
		}
		res, err := state.KubeClient.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, review, metav1.CreateOptions{})
		if err != nil {
			// The review is granted to every authenticated identity by
			// system:basic-user, so this is an unusual cluster rather than a
			// missing grant. Fall back rather than guess.
			return checkLeaseAccessByRead(ctx, namespace, name)
		}
		if !res.Status.Allowed {
			return fmt.Errorf("not allowed to %s Lease %s/%s: grant %s on coordination.k8s.io leases in that namespace: %s",
				verb, namespace, name, strings.Join(leaseVerbs, "/"), cmp.Or(res.Status.Reason, "no matching RBAC rule"))
		}
	}
	return nil
}

// checkLeaseAccessByRead is the fallback probe for clusters where
// SelfSubjectAccessReview is unavailable. NotFound is the expected state
// before the first election and means the read was authorized.
func checkLeaseAccessByRead(ctx context.Context, namespace, name string) error {
	_, err := state.KubeClient.CoordinationV1().Leases(namespace).Get(ctx, name, metav1.GetOptions{})
	if err == nil || apierrors.IsNotFound(err) {
		return nil
	}
	if apierrors.IsForbidden(err) {
		return fmt.Errorf("no permission to read Lease %s/%s: grant %s on coordination.k8s.io leases in that namespace: %w",
			namespace, name, strings.Join(leaseVerbs, "/"), err)
	}
	return fmt.Errorf("failed to read Lease %s/%s: %w", namespace, name, err)
}

// degradeOrFail decides what an environment that cannot elect means for this
// process: run unelected (the default, so a missing Lease grant never costs
// certificate syncing), or refuse to start (LEADER_ELECTION_REQUIRED, set by
// the chart whenever more than one replica is asked for).
func degradeOrFail(ctx context.Context, reason error, run func(context.Context)) error {
	l := log.WithFields(log.Fields{"fn": "degradeOrFail"})
	if leaderElectionRequired() {
		return fmt.Errorf("leader election is required but unavailable: %w", reason)
	}
	metrics.SetLeaderElectionDegraded(true)
	// Error, not Warn: this is silently load-bearing above one replica, and
	// the metric alone is only visible where metrics are enabled.
	l.WithError(reason).Error("leader election unavailable; reconciling without it — safe for a single replica, but every replica will reconcile every secret, which mints duplicate remote certificates. Grant the Lease RBAC, or set LEADER_ELECTION_ENABLED=false to silence this")
	run(ctx)
	return nil
}

// runWithLeaderElection blocks, running run() only while this process holds the
// lease. It returns when ctx is cancelled or when leadership is lost.
func runWithLeaderElection(ctx context.Context, run func(context.Context)) error {
	l := log.WithFields(log.Fields{"fn": "runWithLeaderElection"})

	namespace, err := leaderElectionNamespace()
	if err != nil {
		return degradeOrFail(ctx, err, run)
	}
	lockName := cmp.Or(os.Getenv("LEADER_ELECTION_LOCK_NAME"), defaultLockName)
	identity := leaderElectionIdentity()
	lease, renew, retry := leaderElectionTimings()

	if err := checkLeaseCapability(ctx, namespace, lockName); err != nil {
		return degradeOrFail(ctx, err, run)
	}
	metrics.SetLeaderElectionDegraded(false)

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
