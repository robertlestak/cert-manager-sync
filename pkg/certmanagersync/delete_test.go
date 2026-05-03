package certmanagersync

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/record"
)

// tlssecretConfig wraps a Config map into a GenericSecretSyncConfig for tests.
func tlssecretConfig(c map[string]string) tlssecret.GenericSecretSyncConfig {
	return tlssecret.GenericSecretSyncConfig{Config: c}
}

// withFakeClientset replaces the package-level secretsClient with one backed by
// the supplied fake clientset, restoring the original when the test ends.
func withFakeClientset(t *testing.T, objs ...runtime.Object) *fake.Clientset {
	t.Helper()
	cs := fake.NewSimpleClientset(objs...)
	prev := secretsClient
	secretsClient = func(namespace string) patcher {
		return cs.CoreV1().Secrets(namespace)
	}
	t.Cleanup(func() { secretsClient = prev })
	// Use a fresh fake recorder per test so events don't leak between tests.
	prevRec := state.EventRecorder
	state.EventRecorder = record.NewFakeRecorder(50)
	t.Cleanup(func() { state.EventRecorder = prevRec })
	return cs
}

func clearDeleteEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DELETE_POLICY", "")
	t.Setenv("MAX_DELETE_ATTEMPTS", "")
	t.Setenv("DELETE_BLOCKING", "")
}

// makeSecret builds a base secret pre-loaded into the fake clientset.
func makeSecret(name, namespace string, annotations map[string]string, finalizers []string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Annotations: annotations,
			Finalizers:  finalizers,
		},
	}
}

func TestEnsureFinalizer_AddsWhenMissing(t *testing.T) {
	clearDeleteEnv(t)
	s := makeSecret("s1", "ns", nil, nil)
	cs := withFakeClientset(t, s)

	patched, err := EnsureFinalizer(context.Background(), s)
	require.NoError(t, err)
	assert.True(t, patched)
	// EnsureFinalizer must NOT mutate the in-memory secret (shared informer cache).
	assert.NotContains(t, s.Finalizers, state.FinalizerName(), "in-memory secret must not be mutated")

	got, err := cs.CoreV1().Secrets("ns").Get(context.Background(), "s1", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Contains(t, got.Finalizers, state.FinalizerName())
}

func TestEnsureFinalizer_NoOpWhenAlreadyPresent(t *testing.T) {
	clearDeleteEnv(t)
	s := makeSecret("s1", "ns", nil, []string{state.FinalizerName()})
	cs := withFakeClientset(t, s)

	patched, err := EnsureFinalizer(context.Background(), s)
	require.NoError(t, err)
	assert.False(t, patched)

	// Verify no PATCH was issued.
	for _, a := range cs.Actions() {
		assert.NotEqual(t, "patch", a.GetVerb(), "unexpected patch action")
	}
}

func TestEnsureFinalizer_SkipsIfDeletionTimestamp(t *testing.T) {
	clearDeleteEnv(t)
	now := metav1.Now()
	s := makeSecret("s1", "ns", nil, nil)
	s.DeletionTimestamp = &now
	withFakeClientset(t, s)

	patched, err := EnsureFinalizer(context.Background(), s)
	require.NoError(t, err)
	assert.False(t, patched, "should not add finalizer to a secret already being deleted")
}

func TestEnsureFinalizer_PreservesExistingFinalizers(t *testing.T) {
	clearDeleteEnv(t)
	s := makeSecret("s1", "ns", nil, []string{"other.example.com/foo"})
	cs := withFakeClientset(t, s)

	_, err := EnsureFinalizer(context.Background(), s)
	require.NoError(t, err)

	got, err := cs.CoreV1().Secrets("ns").Get(context.Background(), "s1", metav1.GetOptions{})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"other.example.com/foo", state.FinalizerName()}, got.Finalizers)
}

func TestRemoveFinalizer_RemovesAndPatches(t *testing.T) {
	clearDeleteEnv(t)
	s := makeSecret("s1", "ns", nil, []string{"other.example.com/foo", state.FinalizerName()})
	cs := withFakeClientset(t, s)

	patched, err := RemoveFinalizer(context.Background(), s)
	require.NoError(t, err)
	assert.True(t, patched)
	// RemoveFinalizer must NOT mutate the in-memory secret (shared informer cache).
	assert.Contains(t, s.Finalizers, state.FinalizerName(), "in-memory secret must not be mutated")

	got, err := cs.CoreV1().Secrets("ns").Get(context.Background(), "s1", metav1.GetOptions{})
	require.NoError(t, err)
	assert.NotContains(t, got.Finalizers, state.FinalizerName())
	assert.Contains(t, got.Finalizers, "other.example.com/foo")
}

func TestRemoveFinalizer_NoOpWhenAbsent(t *testing.T) {
	clearDeleteEnv(t)
	s := makeSecret("s1", "ns", nil, []string{"other/foo"})
	cs := withFakeClientset(t, s)
	patched, err := RemoveFinalizer(context.Background(), s)
	require.NoError(t, err)
	assert.False(t, patched)
	for _, a := range cs.Actions() {
		assert.NotEqual(t, "patch", a.GetVerb())
	}
}

// registerStubStore replaces NewStore for the duration of the test with one that
// returns the supplied stubs by store type.
func registerStubStore(t *testing.T, stubs map[string]RemoteStore) {
	t.Helper()
	prev := newStoreFn
	newStoreFn = func(storeType string) (RemoteStore, error) {
		s, ok := stubs[storeType]
		if !ok {
			return nil, errors.New("no stub registered for " + storeType)
		}
		return s, nil
	}
	t.Cleanup(func() { newStoreFn = prev })
}

func TestHandleSecretDelete_Idempotent_NoFinalizer(t *testing.T) {
	clearDeleteEnv(t)
	s := makeSecret("s1", "ns", map[string]string{
		state.DeletePolicyAnnotation(): state.DeletePolicyDelete,
	}, nil)
	withFakeClientset(t, s)
	require.NoError(t, HandleSecretDelete(s))
}

func TestHandleSecretDelete_RemovesFinalizer_WhenPolicyRetain(t *testing.T) {
	clearDeleteEnv(t)
	s := makeSecret("s1", "ns",
		map[string]string{state.DeletePolicyAnnotation(): state.DeletePolicyRetain},
		[]string{state.FinalizerName()})
	cs := withFakeClientset(t, s)
	require.NoError(t, HandleSecretDelete(s))
	got, err := cs.CoreV1().Secrets("ns").Get(context.Background(), "s1", metav1.GetOptions{})
	require.NoError(t, err)
	assert.NotContains(t, got.Finalizers, state.FinalizerName())
}

func TestHandleSecretDelete_AllStoresSucceed_RemovesFinalizer(t *testing.T) {
	clearDeleteEnv(t)
	annot := map[string]string{
		state.DeletePolicyAnnotation():       state.DeletePolicyDelete,
		state.OperatorName + "/acm-region":   "us-east-1",
		state.OperatorName + "/vault-path":   "kv/data/test",
	}
	s := makeSecret("s1", "ns", annot, []string{state.FinalizerName()})
	cs := withFakeClientset(t, s)
	acmStub := &fakeStore{}
	vaultStub := &fakeStore{}
	registerStubStore(t, map[string]RemoteStore{
		"acm":   acmStub,
		"vault": vaultStub,
	})

	require.NoError(t, HandleSecretDelete(s))
	assert.Equal(t, 1, acmStub.deleteCnt)
	assert.Equal(t, 1, vaultStub.deleteCnt)

	got, err := cs.CoreV1().Secrets("ns").Get(context.Background(), "s1", metav1.GetOptions{})
	require.NoError(t, err)
	assert.NotContains(t, got.Finalizers, state.FinalizerName())
}

func TestHandleSecretDelete_StoreWithoutDeleteSupport_IsSkipped(t *testing.T) {
	clearDeleteEnv(t)
	annot := map[string]string{
		state.DeletePolicyAnnotation():         state.DeletePolicyDelete,
		state.OperatorName + "/imperva-siteid": "123",
	}
	s := makeSecret("s1", "ns", annot, []string{state.FinalizerName()})
	cs := withFakeClientset(t, s)
	stub := &nonDeletableFakeStore{}
	registerStubStore(t, map[string]RemoteStore{"imperva": stub})

	require.NoError(t, HandleSecretDelete(s))
	// Confirms FromConfig ran (proves the delete path reached the store) but no Delete was called.
	assert.Equal(t, "123", stub.gotConfig.Config["siteid"])

	got, err := cs.CoreV1().Secrets("ns").Get(context.Background(), "s1", metav1.GetOptions{})
	require.NoError(t, err)
	assert.NotContains(t, got.Finalizers, state.FinalizerName())
}

func TestHandleSecretDelete_FailureRetries_KeepsFinalizer(t *testing.T) {
	clearDeleteEnv(t)
	annot := map[string]string{
		state.DeletePolicyAnnotation():     state.DeletePolicyDelete,
		state.OperatorName + "/acm-region": "us-east-1",
	}
	s := makeSecret("s1", "ns", annot, []string{state.FinalizerName()})
	cs := withFakeClientset(t, s)
	stub := &fakeStore{deleteErr: errors.New("api down")}
	registerStubStore(t, map[string]RemoteStore{"acm": stub})

	err := HandleSecretDelete(s)
	require.Error(t, err)

	got, err2 := cs.CoreV1().Secrets("ns").Get(context.Background(), "s1", metav1.GetOptions{})
	require.NoError(t, err2)
	assert.Contains(t, got.Finalizers, state.FinalizerName(), "finalizer must remain on failure")
	assert.Equal(t, "1", got.Annotations[state.DeleteAttemptsAnnotation()])
	assert.NotEmpty(t, got.Annotations[state.NextDeleteAnnotation()])
	// Verify the next-delete is parseable and roughly in the future.
	parsed, perr := time.Parse(time.RFC3339, got.Annotations[state.NextDeleteAnnotation()])
	require.NoError(t, perr)
	assert.True(t, parsed.After(time.Now().Add(-time.Second)))
}

func TestHandleSecretDelete_BackoffSkipsUntilDue(t *testing.T) {
	clearDeleteEnv(t)
	future := time.Now().Add(time.Hour).Format(time.RFC3339)
	annot := map[string]string{
		state.DeletePolicyAnnotation():       state.DeletePolicyDelete,
		state.NextDeleteAnnotation():         future,
		state.OperatorName + "/acm-region":   "us-east-1",
	}
	s := makeSecret("s1", "ns", annot, []string{state.FinalizerName()})
	withFakeClientset(t, s)
	stub := &fakeStore{deleteErr: errors.New("should not be called")}
	registerStubStore(t, map[string]RemoteStore{"acm": stub})

	require.NoError(t, HandleSecretDelete(s))
	assert.Equal(t, 0, stub.deleteCnt, "delete must not run before backoff elapses")
}

func TestHandleSecretDelete_GivesUpAfterMaxAttempts(t *testing.T) {
	clearDeleteEnv(t)
	t.Setenv("MAX_DELETE_ATTEMPTS", "3")
	t.Setenv("DELETE_BLOCKING", "false")
	annot := map[string]string{
		state.DeletePolicyAnnotation():           state.DeletePolicyDelete,
		state.DeleteAttemptsAnnotation():         "2",
		state.OperatorName + "/acm-region":       "us-east-1",
	}
	s := makeSecret("s1", "ns", annot, []string{state.FinalizerName()})
	cs := withFakeClientset(t, s)
	stub := &fakeStore{deleteErr: errors.New("permafail")}
	registerStubStore(t, map[string]RemoteStore{"acm": stub})

	// Returns nil because we gave up rather than asking the caller to retry.
	require.NoError(t, HandleSecretDelete(s))
	got, err := cs.CoreV1().Secrets("ns").Get(context.Background(), "s1", metav1.GetOptions{})
	require.NoError(t, err)
	assert.NotContains(t, got.Finalizers, state.FinalizerName(), "finalizer force-removed when DELETE_BLOCKING=false")
}

func TestHandleSecretDelete_DefaultBlocking_NeverGivesUp(t *testing.T) {
	// Verifies that the default (DELETE_BLOCKING unset) is blocking=true:
	// even past MAX_DELETE_ATTEMPTS the finalizer must remain so the user
	// is forced to fix the underlying issue rather than silently orphaning
	// remote state.
	clearDeleteEnv(t)
	t.Setenv("MAX_DELETE_ATTEMPTS", "3")
	annot := map[string]string{
		state.DeletePolicyAnnotation():     state.DeletePolicyDelete,
		state.DeleteAttemptsAnnotation():   "99",
		state.OperatorName + "/acm-region": "us-east-1",
	}
	s := makeSecret("s1", "ns", annot, []string{state.FinalizerName()})
	cs := withFakeClientset(t, s)
	stub := &fakeStore{deleteErr: errors.New("permafail")}
	registerStubStore(t, map[string]RemoteStore{"acm": stub})

	err := HandleSecretDelete(s)
	require.Error(t, err)
	got, gerr := cs.CoreV1().Secrets("ns").Get(context.Background(), "s1", metav1.GetOptions{})
	require.NoError(t, gerr)
	assert.Contains(t, got.Finalizers, state.FinalizerName(), "default DELETE_BLOCKING (true) must keep finalizer past max attempts")
}

func TestHandleSecretDelete_BlockingNeverGivesUp(t *testing.T) {
	clearDeleteEnv(t)
	t.Setenv("MAX_DELETE_ATTEMPTS", "3")
	t.Setenv("DELETE_BLOCKING", "true")
	annot := map[string]string{
		state.DeletePolicyAnnotation():           state.DeletePolicyDelete,
		state.DeleteAttemptsAnnotation():         strconv.Itoa(99),
		state.OperatorName + "/acm-region":       "us-east-1",
	}
	s := makeSecret("s1", "ns", annot, []string{state.FinalizerName()})
	cs := withFakeClientset(t, s)
	stub := &fakeStore{deleteErr: errors.New("permafail")}
	registerStubStore(t, map[string]RemoteStore{"acm": stub})

	err := HandleSecretDelete(s)
	require.Error(t, err)
	got, gerr := cs.CoreV1().Secrets("ns").Get(context.Background(), "s1", metav1.GetOptions{})
	require.NoError(t, gerr)
	assert.Contains(t, got.Finalizers, state.FinalizerName(), "finalizer must remain in blocking mode")
}

func TestHandleSecretDelete_ZeroMaxAttemptsRetriesForever(t *testing.T) {
	clearDeleteEnv(t)
	t.Setenv("MAX_DELETE_ATTEMPTS", "0")
	t.Setenv("DELETE_BLOCKING", "false")
	annot := map[string]string{
		state.DeletePolicyAnnotation():     state.DeletePolicyDelete,
		state.DeleteAttemptsAnnotation():   "9999",
		state.OperatorName + "/acm-region": "us-east-1",
	}
	s := makeSecret("s1", "ns", annot, []string{state.FinalizerName()})
	cs := withFakeClientset(t, s)
	stub := &fakeStore{deleteErr: errors.New("permafail")}
	registerStubStore(t, map[string]RemoteStore{"acm": stub})

	err := HandleSecretDelete(s)
	require.Error(t, err)
	got, gerr := cs.CoreV1().Secrets("ns").Get(context.Background(), "s1", metav1.GetOptions{})
	require.NoError(t, gerr)
	assert.Contains(t, got.Finalizers, state.FinalizerName(), "MAX_DELETE_ATTEMPTS=0 must retry forever")
}

func TestHandleSecretDelete_PartialFailure_KeepsFinalizer(t *testing.T) {
	clearDeleteEnv(t)
	annot := map[string]string{
		state.DeletePolicyAnnotation():     state.DeletePolicyDelete,
		state.OperatorName + "/acm-region": "us-east-1",
		state.OperatorName + "/vault-path": "kv/data/test",
	}
	s := makeSecret("s1", "ns", annot, []string{state.FinalizerName()})
	cs := withFakeClientset(t, s)
	good := &fakeStore{}
	bad := &fakeStore{deleteErr: errors.New("boom")}
	registerStubStore(t, map[string]RemoteStore{"acm": bad, "vault": good})

	err := HandleSecretDelete(s)
	require.Error(t, err)
	assert.Equal(t, 1, good.deleteCnt)
	assert.Equal(t, 1, bad.deleteCnt)

	got, gerr := cs.CoreV1().Secrets("ns").Get(context.Background(), "s1", metav1.GetOptions{})
	require.NoError(t, gerr)
	assert.Contains(t, got.Finalizers, state.FinalizerName(), "any failure keeps finalizer")
}

func TestCalculateNextDeleteRetry(t *testing.T) {
	cases := []struct {
		attempts int
		min, max time.Duration
	}{
		{attempts: 0, min: 30 * time.Second, max: 90 * time.Second},
		{attempts: 1, min: 30 * time.Second, max: 90 * time.Second},
		{attempts: 2, min: 90 * time.Second, max: 150 * time.Second},
		{attempts: 5, min: 15 * time.Minute, max: 17 * time.Minute},
		{attempts: 100, min: 31 * time.Hour, max: 33 * time.Hour},
	}
	for _, c := range cases {
		got := calculateNextDeleteRetry(c.attempts).Sub(time.Now())
		assert.True(t, got >= c.min && got <= c.max, "attempts=%d delay=%s expected in [%s,%s]", c.attempts, got, c.min, c.max)
	}
}

func TestWithSecretNamespaceDefault(t *testing.T) {
	cases := []struct {
		name      string
		in        map[string]string
		namespace string
		wantName  string
	}{
		{
			name:      "rewrites bare secret-name with K8s secret namespace",
			in:        map[string]string{"secret-name": "creds"},
			namespace: "team-a",
			wantName:  "team-a/creds",
		},
		{
			name:      "leaves namespaced secret-name alone",
			in:        map[string]string{"secret-name": "other/creds"},
			namespace: "team-a",
			wantName:  "other/creds",
		},
		{
			name:      "no-op when secret-name is absent (filepath, vault)",
			in:        map[string]string{"path": "kv/foo"},
			namespace: "team-a",
			wantName:  "",
		},
		{
			name:      "no-op when namespace is empty",
			in:        map[string]string{"secret-name": "creds"},
			namespace: "",
			wantName:  "creds",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			origConfig := make(map[string]string, len(tc.in))
			for k, v := range tc.in {
				origConfig[k] = v
			}
			in := tlssecretConfig(tc.in)
			got := withSecretNamespaceDefault(in, tc.namespace)
			assert.Equal(t, tc.wantName, got.Config["secret-name"])
			// Caller's map must remain untouched.
			assert.Equal(t, origConfig, tc.in, "input config must not be mutated")
		})
	}
}

func TestHandleSecretDelete_PassesNamespacedCredentialsSecret(t *testing.T) {
	clearDeleteEnv(t)
	annot := map[string]string{
		state.DeletePolicyAnnotation():          state.DeletePolicyDelete,
		state.OperatorName + "/acm-secret-name": "aws-creds",
	}
	s := makeSecret("s1", "team-a", annot, []string{state.FinalizerName()})
	withFakeClientset(t, s)
	stub := &fakeStore{}
	registerStubStore(t, map[string]RemoteStore{"acm": stub})
	require.NoError(t, HandleSecretDelete(s))
	assert.Equal(t, "team-a/aws-creds", stub.gotConfig.Config["secret-name"],
		"HandleSecretDelete must default secret-name to <secretNamespace>/<name> so per-store FromConfig sets SecretNamespace")
}

func TestHandleSecretDelete_PreservesExplicitNamespacedSecretName(t *testing.T) {
	clearDeleteEnv(t)
	annot := map[string]string{
		state.DeletePolicyAnnotation():          state.DeletePolicyDelete,
		state.OperatorName + "/acm-secret-name": "shared/aws-creds",
	}
	s := makeSecret("s1", "team-a", annot, []string{state.FinalizerName()})
	withFakeClientset(t, s)
	stub := &fakeStore{}
	registerStubStore(t, map[string]RemoteStore{"acm": stub})
	require.NoError(t, HandleSecretDelete(s))
	assert.Equal(t, "shared/aws-creds", stub.gotConfig.Config["secret-name"],
		"explicit cross-namespace secret-name must be preserved")
}

func TestPatchDeleteRetry_WritesAnnotations(t *testing.T) {
	clearDeleteEnv(t)
	s := makeSecret("s1", "ns", nil, nil)
	cs := withFakeClientset(t, s)
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	require.NoError(t, patchDeleteRetry(context.Background(), s, 7, at))

	got, err := cs.CoreV1().Secrets("ns").Get(context.Background(), "s1", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "7", got.Annotations[state.DeleteAttemptsAnnotation()])
	assert.Equal(t, at.Format(time.RFC3339), got.Annotations[state.NextDeleteAnnotation()])
}

// EnsureFinalizer must use strategic merge patch so that finalizers added
// by other controllers between our Read and Patch are not clobbered (JSON
// merge patch would replace the entire array).
func TestEnsureFinalizer_UsesStrategicMergePatch(t *testing.T) {
	clearDeleteEnv(t)
	s := makeSecret("s1", "ns", nil, nil)
	cs := withFakeClientset(t, s)
	_, err := EnsureFinalizer(context.Background(), s)
	require.NoError(t, err)
	var saw bool
	for _, a := range cs.Actions() {
		if pa, ok := a.(clienttesting.PatchAction); ok {
			assert.Equal(t, types.StrategicMergePatchType, pa.GetPatchType(),
				"finalizer patches must use strategic merge to avoid clobbering other controllers' finalizers")
			saw = true
		}
	}
	assert.True(t, saw, "expected at least one Patch action")
}

// RemoveFinalizer must use strategic merge patch with $deleteFromPrimitiveList
// so that other controllers' finalizers on the secret are preserved.
func TestRemoveFinalizer_UsesStrategicMergePatch(t *testing.T) {
	clearDeleteEnv(t)
	s := makeSecret("s1", "ns", nil, []string{"other.example.com/foo", state.FinalizerName()})
	cs := withFakeClientset(t, s)
	_, err := RemoveFinalizer(context.Background(), s)
	require.NoError(t, err)
	var saw bool
	for _, a := range cs.Actions() {
		if pa, ok := a.(clienttesting.PatchAction); ok {
			assert.Equal(t, types.StrategicMergePatchType, pa.GetPatchType())
			saw = true
		}
	}
	assert.True(t, saw, "expected at least one Patch action")
}
