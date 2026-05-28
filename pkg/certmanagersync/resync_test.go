package certmanagersync

import (
	"context"
	"testing"

	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// withFakeKubeClient points state.KubeClient (used by HandleSecret's patch) at
// the supplied fake clientset for the duration of the test.
func withFakeKubeClient(t *testing.T, cs *fake.Clientset) {
	t.Helper()
	prev := state.KubeClient
	state.KubeClient = cs
	t.Cleanup(func() { state.KubeClient = prev })
}

// TestHandleSecret_CachesWriteBackAnnotations_NoResyncLoop is a regression test
// for issue #51. A store hands back bookkeeping annotations (here cloudflare's
// cert-id) on a successful sync. Those annotations are operator-prefixed and so
// are part of HashSecret. The success path must cache the hash of the
// post-write-back annotation set; otherwise the very next reconcile recomputes a
// different hash, treats the cache as stale, and re-syncs forever — each pass
// minting a new remote certificate until the provider's quota is exhausted.
// Exponential backoff cannot prevent this because it only throttles failures.
func TestHandleSecret_CachesWriteBackAnnotations_NoResyncLoop(t *testing.T) {
	clearDeleteEnv(t)
	t.Setenv("CACHE_DISABLE", "")

	s := makeSecret("tls", "ns", map[string]string{
		state.OperatorName + "/sync-enabled":           "true",
		state.OperatorName + "/cloudflare-zone-id":     "zone123",
		state.OperatorName + "/cloudflare-secret-name": "cf-creds",
	}, nil)
	s.Data = map[string][]byte{
		"tls.crt": []byte("cert"),
		"tls.key": []byte("key"),
	}

	cs := withFakeClientset(t, s)
	withFakeKubeClient(t, cs)

	stub := &fakeStore{syncUpdates: map[string]string{"cert-id": "abc123"}}
	registerStubStore(t, map[string]RemoteStore{"cloudflare": stub})

	// First reconcile: cache empty, so the secret syncs and the store returns a
	// cert-id that gets written back as an annotation.
	require.NoError(t, HandleSecret(s))
	assert.Equal(t, 1, stub.syncCnt, "first reconcile should sync once")

	got := mustGetSecret(t, cs, "ns", "tls")
	assert.Equal(t, "abc123", got.Annotations[state.OperatorName+"/cloudflare-cert-id"],
		"store write-back annotation must be persisted")
	require.NotEmpty(t, got.Annotations[state.OperatorName+"/hash"], "cache hash must be written")

	// Second reconcile against the freshly-patched secret: nothing the user owns
	// changed, so the cache must report no change and the store must NOT be hit
	// again. Pre-fix this asserted 2 and exposed the loop.
	require.NoError(t, HandleSecret(got))
	assert.Equal(t, 1, stub.syncCnt, "stable secret must not trigger a re-sync")
}

// TestHandleSecret_ExternalRevertOfWriteBack_NoResyncLoop reproduces the
// GitOps ping-pong from issue #51: a tool like ArgoCD owns the secret manifest
// and keeps resetting the operator's write-back annotation (cloudflare-cert-id)
// to "". The operator fills it on sync, the tool reverts it, and pre-fix the
// operator treated each revert as a material change -- re-syncing and, because
// an empty cert-id takes the create path, minting a new remote certificate every
// pass until the provider quota is exhausted. The fix excludes managed write-back
// annotations from the cache hash, so external churn on them never re-syncs.
func TestHandleSecret_ExternalRevertOfWriteBack_NoResyncLoop(t *testing.T) {
	clearDeleteEnv(t)
	t.Setenv("CACHE_DISABLE", "")

	s := makeSecret("tls", "ns", map[string]string{
		state.OperatorName + "/sync-enabled":           "true",
		state.OperatorName + "/cloudflare-zone-id":     "zone123",
		state.OperatorName + "/cloudflare-secret-name": "cf-creds",
	}, nil)
	s.Data = map[string][]byte{
		"tls.crt": []byte("cert"),
		"tls.key": []byte("key"),
	}

	cs := withFakeClientset(t, s)
	withFakeKubeClient(t, cs)

	stub := &fakeStore{syncUpdates: map[string]string{"cert-id": "abc123"}}
	registerStubStore(t, map[string]RemoteStore{"cloudflare": stub})

	require.NoError(t, HandleSecret(s))
	assert.Equal(t, 1, stub.syncCnt, "first reconcile should sync once")

	// Simulate the GitOps tool reverting the operator's write-back to "" on the
	// persisted object, then reconcile that state.
	reverted := mustGetSecret(t, cs, "ns", "tls")
	reverted.Annotations[state.OperatorName+"/cloudflare-cert-id"] = ""
	require.NoError(t, HandleSecret(reverted))
	assert.Equal(t, 1, stub.syncCnt, "external revert of a write-back annotation must not re-sync")
}

func mustGetSecret(t *testing.T, cs *fake.Clientset, ns, name string) *corev1.Secret {
	t.Helper()
	got, err := cs.CoreV1().Secrets(ns).Get(context.Background(), name, metav1.GetOptions{})
	require.NoError(t, err)
	return got
}
