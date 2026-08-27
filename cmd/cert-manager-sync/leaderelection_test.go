package main

import (
	"context"
	"testing"
	"time"

	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// withFakeKube points state.KubeClient at a fake clientset for the test.
func withFakeKube(t *testing.T, objs ...runtime.Object) *fake.Clientset {
	t.Helper()
	cs := fake.NewSimpleClientset(objs...)
	prev := state.KubeClient
	state.KubeClient = cs
	t.Cleanup(func() { state.KubeClient = prev })
	return cs
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

func TestCheckLeasePermissions(t *testing.T) {
	t.Run("missing lease is the expected pre-election state", func(t *testing.T) {
		withFakeKube(t)
		require.NoError(t, checkLeasePermissions(context.Background(), "ns", "lock"))
	})

	t.Run("forbidden fails fast with an actionable message", func(t *testing.T) {
		cs := withFakeKube(t)
		cs.PrependReactor("get", "leases", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(
				schema.GroupResource{Group: "coordination.k8s.io", Resource: "leases"}, "lock", nil)
		})
		err := checkLeasePermissions(context.Background(), "ns", "lock")
		require.Error(t, err)
		// Without this the operator would spin on Forbidden forever, looking
		// healthy while syncing nothing.
		assert.Contains(t, err.Error(), "coordination.k8s.io")
		assert.Contains(t, err.Error(), "LEADER_ELECTION_ENABLED=false")
	})
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
