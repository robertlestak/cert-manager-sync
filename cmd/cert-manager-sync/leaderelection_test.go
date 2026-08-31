package main

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/robertlestak/cert-manager-sync/internal/metrics"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// clearLeaderElectionEnv unsets every knob so a test starts from documented
// defaults regardless of the ambient environment.
func clearLeaderElectionEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"LEADER_ELECTION_ENABLED",
		"LEADER_ELECTION_REQUIRED",
		"LEADER_ELECTION_NAMESPACE",
		"LEADER_ELECTION_LOCK_NAME",
		"LEADER_ELECTION_LEASE_DURATION",
		"LEADER_ELECTION_RENEW_DEADLINE",
		"LEADER_ELECTION_RETRY_PERIOD",
		"POD_NAMESPACE",
		"POD_NAME",
	} {
		t.Setenv(k, "")
	}
}

// withFakeKube points state.KubeClient at a fake clientset for the test. The
// fake answers every SelfSubjectAccessReview with an empty (deny) status, so
// it is set to allow here: the default posture for these tests is a cluster
// that can elect. Use denyLeaseAccess for the other case.
func withFakeKube(t *testing.T, objs ...runtime.Object) *fake.Clientset {
	t.Helper()
	cs := fake.NewSimpleClientset(objs...)
	allowLeaseAccess(cs)
	prev := state.KubeClient
	state.KubeClient = cs
	t.Cleanup(func() { state.KubeClient = prev })
	return cs
}

// allowLeaseAccess answers every access review with "allowed".
func allowLeaseAccess(cs *fake.Clientset) {
	cs.PrependReactor("create", "selfsubjectaccessreviews", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, &authorizationv1.SelfSubjectAccessReview{
			Status: authorizationv1.SubjectAccessReviewStatus{Allowed: true},
		}, nil
	})
}

// denyLeaseAccess models the cluster in the 1.6.0 upgrade reports: the
// operator's RBAC predates leader election and grants nothing on
// coordination.k8s.io.
func denyLeaseAccess(cs *fake.Clientset, verbs ...string) {
	denied := map[string]bool{}
	for _, v := range verbs {
		denied[v] = true
	}
	cs.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		review := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview)
		allowed := len(denied) > 0 && !denied[review.Spec.ResourceAttributes.Verb]
		return true, &authorizationv1.SelfSubjectAccessReview{
			Status: authorizationv1.SubjectAccessReviewStatus{
				Allowed: allowed,
				Reason:  "no RBAC policy matched",
			},
		}, nil
	})
	cs.PrependReactor("get", "leases", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(
			schema.GroupResource{Group: "coordination.k8s.io", Resource: "leases"}, "lock", nil)
	})
}

func TestLeaderElectionEnabled_DefaultsOn(t *testing.T) {
	clearLeaderElectionEnv(t)
	// Leader election guards against silent, expensive duplicate remote certs,
	// so it must be opt-out rather than opt-in.
	assert.True(t, leaderElectionEnabled(), "leader election must default to enabled")

	t.Setenv("LEADER_ELECTION_ENABLED", "false")
	assert.False(t, leaderElectionEnabled())

	t.Setenv("LEADER_ELECTION_ENABLED", "False")
	assert.False(t, leaderElectionEnabled(), "the opt-out must not be case sensitive")

	t.Setenv("LEADER_ELECTION_ENABLED", "true")
	assert.True(t, leaderElectionEnabled())

	// Anything that is not an explicit opt-out leaves the guard in place.
	t.Setenv("LEADER_ELECTION_ENABLED", "no")
	assert.True(t, leaderElectionEnabled(), "only \"false\" disables leader election")
}

func TestLeaderElectionNamespace_Precedence(t *testing.T) {
	clearLeaderElectionEnv(t)

	t.Setenv("POD_NAMESPACE", "downward-ns")
	ns, err := leaderElectionNamespace()
	require.NoError(t, err)
	assert.Equal(t, "downward-ns", ns)

	t.Setenv("LEADER_ELECTION_NAMESPACE", "explicit-ns")
	ns, err = leaderElectionNamespace()
	require.NoError(t, err)
	assert.Equal(t, "explicit-ns", ns, "explicit config must win over the downward API")
}

func TestLeaderElectionNamespace_UnresolvableIsActionable(t *testing.T) {
	clearLeaderElectionEnv(t)
	// Outside a cluster there is no service account namespace file, so this
	// must fail with a message that names the way out rather than defaulting to
	// some arbitrary namespace the operator has no rights in.
	_, err := leaderElectionNamespace()
	if err == nil {
		t.Skip("running inside a cluster; namespace resolved from the service account")
	}
	assert.Contains(t, err.Error(), "LEADER_ELECTION_NAMESPACE")
	assert.Contains(t, err.Error(), "LEADER_ELECTION_ENABLED=false")
}

func TestLeaderElectionIdentity_UniquePerProcess(t *testing.T) {
	clearLeaderElectionEnv(t)
	t.Setenv("POD_NAME", "cert-manager-sync-0")

	a := leaderElectionIdentity()
	b := leaderElectionIdentity()
	assert.Contains(t, a, "cert-manager-sync-0")
	// A restarted pod reuses its name; identity must not collide with the
	// record its previous incarnation left behind.
	assert.NotEqual(t, a, b, "identity must be unique per process, not per pod name")
}

func TestLeaderElectionTimings(t *testing.T) {
	clearLeaderElectionEnv(t)

	lease, renew, retry := leaderElectionTimings()
	assert.Equal(t, defaultLeaseDuration, lease)
	assert.Equal(t, defaultRenewDeadline, renew)
	assert.Equal(t, defaultRetryPeriod, retry)

	t.Setenv("LEADER_ELECTION_LEASE_DURATION", "30s")
	t.Setenv("LEADER_ELECTION_RENEW_DEADLINE", "20s")
	t.Setenv("LEADER_ELECTION_RETRY_PERIOD", "4s")
	lease, renew, retry = leaderElectionTimings()
	assert.Equal(t, 30*time.Second, lease)
	assert.Equal(t, 20*time.Second, renew)
	assert.Equal(t, 4*time.Second, retry)

	// client-go panics on renewDeadline >= leaseDuration. A bad value in a
	// values.yaml must not take the operator down, so we fall back instead.
	t.Setenv("LEADER_ELECTION_RENEW_DEADLINE", "45s")
	lease, renew, retry = leaderElectionTimings()
	assert.Equal(t, defaultLeaseDuration, lease)
	assert.Equal(t, defaultRenewDeadline, renew)
	assert.Equal(t, defaultRetryPeriod, retry)

	// Unparseable values fall back per-key.
	clearLeaderElectionEnv(t)
	t.Setenv("LEADER_ELECTION_LEASE_DURATION", "fifteen seconds")
	lease, _, _ = leaderElectionTimings()
	assert.Equal(t, defaultLeaseDuration, lease)
}

func TestCheckLeaseCapability(t *testing.T) {
	t.Run("allowed on every verb the lock uses", func(t *testing.T) {
		withFakeKube(t)
		require.NoError(t, checkLeaseCapability(context.Background(), "ns", "lock"))
	})

	t.Run("denied names the verb and the rule to grant", func(t *testing.T) {
		cs := withFakeKube(t)
		denyLeaseAccess(cs, "get", "create", "update")
		err := checkLeaseCapability(context.Background(), "ns", "lock")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "coordination.k8s.io")
		assert.Contains(t, err.Error(), "get/create/update")
	})

	t.Run("read access alone is not capability", func(t *testing.T) {
		// The failure this catches is invisible to a Get probe: the candidate
		// reads the Lease fine, then never acquires or renews it and idles as
		// a healthy-looking replica that syncs nothing.
		cs := withFakeKube(t)
		denyLeaseAccess(cs, "update")
		err := checkLeaseCapability(context.Background(), "ns", "lock")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "update")
	})

	t.Run("falls back to reading the Lease when review is unavailable", func(t *testing.T) {
		cs := withFakeKube(t)
		cs.PrependReactor("create", "selfsubjectaccessreviews", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewNotFound(
				schema.GroupResource{Group: "authorization.k8s.io", Resource: "selfsubjectaccessreviews"}, "")
		})
		// NotFound on the Lease is the expected pre-election state, and proves
		// the read was authorized.
		require.NoError(t, checkLeaseCapability(context.Background(), "ns", "lock"))

		cs.PrependReactor("get", "leases", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(
				schema.GroupResource{Group: "coordination.k8s.io", Resource: "leases"}, "lock", nil)
		})
		assert.Error(t, checkLeaseCapability(context.Background(), "ns", "lock"))
	})
}

func TestRunWithLeaderElection_DegradesWhenClusterCannotElect(t *testing.T) {
	clearLeaderElectionEnv(t)
	fastElection(t)
	t.Setenv("LEADER_ELECTION_NAMESPACE", "ns")
	cs := withFakeKube(t)
	denyLeaseAccess(cs, "get", "create", "update")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ran := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- runWithLeaderElection(ctx, func(runCtx context.Context) {
			close(ran)
			<-runCtx.Done()
		})
	}()

	// The whole point: an operator that synced certificates before 1.6.0 keeps
	// syncing them after it, even though the Lease RBAC has not been applied.
	select {
	case <-ran:
	case <-time.After(10 * time.Second):
		t.Fatal("missing Lease RBAC stopped the controller instead of degrading")
	}
	assert.Equal(t, 1.0, gaugeValue(t, metrics.LeaderElectionDegraded),
		"running unelected must be visible to alerting")

	cancel()
	select {
	case err := <-done:
		// Degrading is not a failure: a non-nil error here becomes os.Exit(1)
		// in main, which is the crash loop this change exists to remove.
		assert.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("runWithLeaderElection did not return after cancellation")
	}
}

func TestRunWithLeaderElection_RequiredRefusesToDegrade(t *testing.T) {
	clearLeaderElectionEnv(t)
	fastElection(t)
	t.Setenv("LEADER_ELECTION_NAMESPACE", "ns")
	t.Setenv("LEADER_ELECTION_REQUIRED", "true")
	cs := withFakeKube(t)
	denyLeaseAccess(cs, "get", "create", "update")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Above one replica, unelected is not a degraded mode — it is every
	// replica taking its store's create path and minting duplicate remote
	// certificates. Refusing to start is the safe answer there.
	err := runWithLeaderElection(ctx, func(context.Context) {
		t.Fatal("reconciled without a lease while leader election was required")
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

func TestRunWithLeaderElection_DegradesWhenNamespaceUnresolvable(t *testing.T) {
	clearLeaderElectionEnv(t)
	withFakeKube(t)
	if _, err := leaderElectionNamespace(); err == nil {
		t.Skip("running inside a cluster; namespace resolved from the service account")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ran := make(chan struct{})
	go func() {
		_ = runWithLeaderElection(ctx, func(runCtx context.Context) {
			close(ran)
			<-runCtx.Done()
		})
	}()
	select {
	case <-ran:
	case <-time.After(10 * time.Second):
		t.Fatal("an unresolvable namespace must degrade, not stop the controller")
	}
}

// gaugeValue reads a plain gauge without reaching into prometheus internals
// beyond the documented Write path.
func gaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	var m dto.Metric
	require.NoError(t, g.Write(&m))
	return m.GetGauge().GetValue()
}

// fastElection points the timing knobs at test-scale durations while keeping
// client-go's leaseDuration > renewDeadline > retryPeriod*JitterFactor invariant.
func fastElection(t *testing.T) {
	t.Helper()
	t.Setenv("LEADER_ELECTION_LEASE_DURATION", "2s")
	t.Setenv("LEADER_ELECTION_RENEW_DEADLINE", "1s")
	t.Setenv("LEADER_ELECTION_RETRY_PERIOD", "200ms")
}

func TestRunWithLeaderElection_AcquiresAndReleases(t *testing.T) {
	clearLeaderElectionEnv(t)
	fastElection(t)
	t.Setenv("LEADER_ELECTION_NAMESPACE", "ns")
	withFakeKube(t)

	ctx, cancel := context.WithCancel(context.Background())
	leading := make(chan struct{})
	done := make(chan error, 1)

	go func() {
		done <- runWithLeaderElection(ctx, func(runCtx context.Context) {
			close(leading)
			<-runCtx.Done()
		})
	}()

	select {
	case <-leading:
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("uncontested candidate never acquired leadership")
	}

	// A clean shutdown is not a demotion: it must not be reported as an error,
	// which is what drives the non-zero exit in main.
	cancel()
	select {
	case err := <-done:
		assert.NoError(t, err, "shutdown must not be reported as lost leadership")
	case <-time.After(10 * time.Second):
		t.Fatal("runWithLeaderElection did not return after cancellation")
	}
}

func TestRunWithLeaderElection_YieldsToExistingHolder(t *testing.T) {
	clearLeaderElectionEnv(t)
	fastElection(t)
	t.Setenv("LEADER_ELECTION_NAMESPACE", "ns")

	// A peer holds a lease it is actively renewing. This is the case that
	// matters: without election both replicas would reconcile the same secret
	// and each take the store's create path. See issue #48.
	held := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Name: defaultLockName, Namespace: "ns"},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity:       ptr("the-other-replica"),
			LeaseDurationSeconds: ptr(int32(3600)),
			AcquireTime:          microNow(),
			RenewTime:            microNow(),
		},
	}
	withFakeKube(t, held)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	leading := make(chan struct{})
	go func() {
		_ = runWithLeaderElection(ctx, func(runCtx context.Context) {
			close(leading)
			<-runCtx.Done()
		})
	}()

	select {
	case <-leading:
		t.Fatal("candidate started reconciling while another replica held the lease")
	case <-time.After(3 * time.Second):
		// Correct: it is still contending, not reconciling.
	}
}

func ptr[T any](v T) *T { return &v }

func microNow() *metav1.MicroTime {
	now := metav1.NowMicro()
	return &now
}
