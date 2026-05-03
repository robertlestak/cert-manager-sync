package main

import (
	"context"
	"testing"

	"github.com/robertlestak/cert-manager-sync/pkg/state"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type fns struct {
	syncCalls   int
	deleteCalls int
	ensureCalls int
	removeCalls int
	syncErr     error
	deleteErr   error
	ensureErr   error
	removeErr   error
}

// install replaces the package-level handler vars with stubs that record calls
// and restores them when the test ends.
func (f *fns) install(t *testing.T) {
	t.Helper()
	prevSync := handleSecretFn
	prevDel := handleSecretDeleteFn
	prevEnsure := ensureFinalizerFn
	prevRemove := removeFinalizerFn

	handleSecretFn = func(_ *corev1.Secret) error {
		f.syncCalls++
		return f.syncErr
	}
	handleSecretDeleteFn = func(_ *corev1.Secret) error {
		f.deleteCalls++
		return f.deleteErr
	}
	ensureFinalizerFn = func(_ context.Context, _ *corev1.Secret) (bool, error) {
		f.ensureCalls++
		return f.ensureErr == nil, f.ensureErr
	}
	removeFinalizerFn = func(_ context.Context, _ *corev1.Secret) (bool, error) {
		f.removeCalls++
		return f.removeErr == nil, f.removeErr
	}

	t.Cleanup(func() {
		handleSecretFn = prevSync
		handleSecretDeleteFn = prevDel
		ensureFinalizerFn = prevEnsure
		removeFinalizerFn = prevRemove
	})
}

func clearDeleteEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DELETE_POLICY", "")
	t.Setenv("MAX_DELETE_ATTEMPTS", "")
	t.Setenv("DELETE_BLOCKING", "")
	t.Setenv("ENABLED_NAMESPACES", "")
	t.Setenv("DISABLED_NAMESPACES", "")
	t.Setenv("SECRETS_NAMESPACE", "")
}

func watchedSecret(name string, extraAnnots map[string]string, finalizers []string) *corev1.Secret {
	annotations := map[string]string{
		state.OperatorName + "/sync-enabled": "true",
	}
	for k, v := range extraAnnots {
		annotations[k] = v
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   "ns",
			Annotations: annotations,
			Finalizers:  finalizers,
		},
		Data: map[string][]byte{
			"tls.crt": []byte("cert"),
			"tls.key": []byte("key"),
		},
	}
}

func TestReconcileSecret_NotWatched_NoOp(t *testing.T) {
	clearDeleteEnv(t)
	f := &fns{}
	f.install(t)
	s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "x", Namespace: "ns"}}
	reconcileSecret(log.NewEntry(log.New()), s)
	assert.Zero(t, f.syncCalls+f.deleteCalls+f.ensureCalls+f.removeCalls)
}

func TestReconcileSecret_WatchedRetainPolicy_NoFinalizer_JustSyncs(t *testing.T) {
	clearDeleteEnv(t)
	f := &fns{}
	f.install(t)
	s := watchedSecret("s", nil, nil)
	reconcileSecret(log.NewEntry(log.New()), s)
	assert.Equal(t, 1, f.syncCalls)
	assert.Equal(t, 0, f.ensureCalls)
	assert.Equal(t, 0, f.removeCalls)
	assert.Equal(t, 0, f.deleteCalls)
}

func TestReconcileSecret_WatchedDeletePolicy_AddsFinalizerThenSyncs(t *testing.T) {
	clearDeleteEnv(t)
	f := &fns{}
	f.install(t)
	s := watchedSecret("s", map[string]string{
		state.DeletePolicyAnnotation(): state.DeletePolicyDelete,
	}, nil)
	reconcileSecret(log.NewEntry(log.New()), s)
	assert.Equal(t, 1, f.ensureCalls)
	assert.Equal(t, 1, f.syncCalls)
}

func TestReconcileSecret_WatchedDeletePolicy_GlobalEnv(t *testing.T) {
	clearDeleteEnv(t)
	t.Setenv("DELETE_POLICY", state.DeletePolicyDelete)
	f := &fns{}
	f.install(t)
	s := watchedSecret("s", nil, nil)
	reconcileSecret(log.NewEntry(log.New()), s)
	assert.Equal(t, 1, f.ensureCalls, "global env should trigger finalizer ensure")
	assert.Equal(t, 1, f.syncCalls)
}

func TestReconcileSecret_PolicyFlipsToRetain_RemovesFinalizer(t *testing.T) {
	clearDeleteEnv(t)
	f := &fns{}
	f.install(t)
	s := watchedSecret("s", map[string]string{
		state.DeletePolicyAnnotation(): state.DeletePolicyRetain,
	}, []string{state.FinalizerName()})
	reconcileSecret(log.NewEntry(log.New()), s)
	assert.Equal(t, 1, f.removeCalls)
	assert.Equal(t, 0, f.ensureCalls)
	assert.Equal(t, 1, f.syncCalls)
}

func TestReconcileSecret_NoLongerWatched_DropsFinalizer(t *testing.T) {
	clearDeleteEnv(t)
	f := &fns{}
	f.install(t)
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "s",
			Namespace:  "ns",
			Finalizers: []string{state.FinalizerName()},
		},
	}
	reconcileSecret(log.NewEntry(log.New()), s)
	assert.Equal(t, 1, f.removeCalls, "finalizer should be removed when secret stops being watched")
	assert.Equal(t, 0, f.syncCalls, "sync should not run for unwatched secret")
}

func TestReconcileSecret_DeletionTimestamp_RoutesToDelete(t *testing.T) {
	clearDeleteEnv(t)
	f := &fns{}
	f.install(t)
	now := metav1.Now()
	s := watchedSecret("s", map[string]string{
		state.DeletePolicyAnnotation(): state.DeletePolicyDelete,
	}, []string{state.FinalizerName()})
	s.DeletionTimestamp = &now
	reconcileSecret(log.NewEntry(log.New()), s)
	assert.Equal(t, 1, f.deleteCalls)
	assert.Equal(t, 0, f.syncCalls, "sync must not run for a secret being deleted")
	assert.Equal(t, 0, f.ensureCalls)
}

func TestReconcileSecret_DeletionTimestamp_NoFinalizer_NoOp(t *testing.T) {
	clearDeleteEnv(t)
	f := &fns{}
	f.install(t)
	now := metav1.Now()
	s := watchedSecret("s", nil, nil)
	s.DeletionTimestamp = &now
	reconcileSecret(log.NewEntry(log.New()), s)
	// SecretDeletePending requires both timestamp and finalizer; without both, no delete handling.
	assert.Equal(t, 0, f.deleteCalls)
	// Sync should also not run because SecretWatched is true but the secret is already gone-ish
	// — we still call sync because reconcileSecret doesn't gate on DeletionTimestamp absent finalizer.
	// That's intentional: nothing is owed by the operator, and the cache will skip fast.
	assert.Equal(t, 1, f.syncCalls)
}

func TestReconcileSecret_DeleteHandlerError_Logged(t *testing.T) {
	clearDeleteEnv(t)
	f := &fns{deleteErr: assertErr("boom")}
	f.install(t)
	now := metav1.Now()
	s := watchedSecret("s", map[string]string{
		state.DeletePolicyAnnotation(): state.DeletePolicyDelete,
	}, []string{state.FinalizerName()})
	s.DeletionTimestamp = &now
	// Should not panic; reconcileSecret swallows the error after logging.
	reconcileSecret(log.NewEntry(log.New()), s)
	assert.Equal(t, 1, f.deleteCalls)
}

func TestReconcileSecret_EnsureFinalizerError_StillAttemptsSync(t *testing.T) {
	clearDeleteEnv(t)
	f := &fns{ensureErr: assertErr("api boom")}
	f.install(t)
	s := watchedSecret("s", map[string]string{
		state.DeletePolicyAnnotation(): state.DeletePolicyDelete,
	}, nil)
	reconcileSecret(log.NewEntry(log.New()), s)
	assert.Equal(t, 1, f.ensureCalls)
	assert.Equal(t, 1, f.syncCalls, "sync should still run even if finalizer ensure failed")
}

// Confirms that deletion timestamps without our finalizer don't trigger HandleSecretDelete,
// preventing accidental deletion path activation on secrets the operator never opted in.
func TestReconcileSecret_DeletionTimestamp_OtherFinalizerOnly_NoOp(t *testing.T) {
	clearDeleteEnv(t)
	f := &fns{}
	f.install(t)
	now := metav1.Now()
	s := watchedSecret("s", nil, []string{"other.example.com/foo"})
	s.DeletionTimestamp = &now
	reconcileSecret(log.NewEntry(log.New()), s)
	assert.Equal(t, 0, f.deleteCalls)
}

// Sentinel error helper.
type sentinelErr string

func (e sentinelErr) Error() string { return string(e) }

func assertErr(s string) error { return sentinelErr(s) }

// Make sure unused vars compile-time-wise by referencing in a noop test.
func TestSentinel(t *testing.T) {
	require.Equal(t, "x", sentinelErr("x").Error())
}
