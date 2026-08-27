package certmanagersync

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
)

// acmLikeStore mimics stores/acm: an import with no CertificateArn set creates a
// brand new ACM certificate object; an import with an ARN updates in place.
type acmLikeStore struct {
	mu      *sync.Mutex
	creates *int
	updates *int
	arnSeq  *int
	arn     string
	region  string
}

func (s *acmLikeStore) FromConfig(c tlssecret.GenericSecretSyncConfig) error {
	s.arn = c.Config["certificate-arn"]
	s.region = c.Config["region"]
	return nil
}

func (s *acmLikeStore) Sync(_ *tlssecret.Certificate) (map[string]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.arn == "" {
		*s.creates++
		*s.arnSeq++
		newArn := fmt.Sprintf("arn:aws:acm:%s:1234:certificate/%d", s.region, *s.arnSeq)
		return map[string]string{"certificate-arn": newArn}, nil
	}
	*s.updates++
	return nil, nil
}

// TestInformerSelfTrigger_NoDuplicateImports is a regression test for issue #52.
//
// The operator's own writes to a watched secret -- the delete finalizer patch in
// reconcileSecret and the write-back annotation patch at the end of HandleSecret
// -- are themselves watched updates, so the informer re-delivers snapshots taken
// *before* those writes landed. A reconcile driven by such a snapshot does not
// see acm-certificate-arn.N, so the ACM store takes its create path and imports a
// second certificate, orphaning the one the secret now points at.
//
// This drives the real informer wiring from cmd/cert-manager-sync/main.go against
// a fake API server and asserts the store takes its create path exactly once per
// configured region, no matter how many self-triggered passes the informer makes.
func TestInformerSelfTrigger_NoDuplicateImports(t *testing.T) {
	for _, tc := range []struct {
		name         string
		deletePolicy string
	}{
		{"retain (no finalizer patch)", "retain"},
		{"delete (finalizer patch)", "delete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearDeleteEnv(t)
			t.Setenv("CACHE_DISABLE", "")

			s := makeSecret("tls", "ns", map[string]string{
				state.OperatorName + "/sync-enabled":  "true",
				state.OperatorName + "/delete-policy": tc.deletePolicy,
				state.OperatorName + "/acm-region.0":  "us-east-1",
				state.OperatorName + "/acm-region.1":  "us-west-2",
				state.OperatorName + "/acm-region.2":  "eu-west-1",
			}, nil)
			s.Data = map[string][]byte{"tls.crt": []byte("cert"), "tls.key": []byte("key")}

			cs := fake.NewSimpleClientset()
			prevSecrets := secretsClient
			secretsClient = func(ns string) patcher { return cs.CoreV1().Secrets(ns) }
			t.Cleanup(func() { secretsClient = prevSecrets })
			withFakeKubeClient(t, cs)
			prevRec := state.EventRecorder
			state.EventRecorder = record.NewFakeRecorder(10000)
			t.Cleanup(func() { state.EventRecorder = prevRec })

			var mu sync.Mutex
			creates, updates, seq := 0, 0, 0
			prevStore := newStoreFn
			newStoreFn = func(storeType string) (RemoteStore, error) {
				return &acmLikeStore{mu: &mu, creates: &creates, updates: &updates, arnSeq: &seq}, nil
			}
			t.Cleanup(func() { newStoreFn = prevStore })

			var handled int
			var hmu sync.Mutex
			reconcile := func(sec *corev1.Secret) {
				ctx := context.Background()
				if state.SecretDeletePending(sec) {
					return
				}
				if !state.SecretWatched(sec) {
					return
				}
				if state.EffectiveDeletePolicy(sec) == state.DeletePolicyDelete {
					_, _ = EnsureFinalizer(ctx, sec)
				}
				hmu.Lock()
				handled++
				hmu.Unlock()
				_ = HandleSecret(sec)
			}

			factory := informers.NewSharedInformerFactory(cs, 30*time.Second)
			inf := factory.Core().V1().Secrets().Informer()
			_, err := inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					if sec, ok := obj.(*corev1.Secret); ok {
						reconcile(sec)
					}
				},
				UpdateFunc: func(_, newObj interface{}) {
					if sec, ok := newObj.(*corev1.Secret); ok {
						reconcile(sec)
					}
				},
			})
			require.NoError(t, err)

			stopper := make(chan struct{})
			factory.Start(stopper)
			cache.WaitForCacheSync(stopper, inf.HasSynced)

			_, err = cs.CoreV1().Secrets("ns").Create(context.Background(), s, metav1.CreateOptions{})
			require.NoError(t, err)

			time.Sleep(3 * time.Second)
			close(stopper)

			mu.Lock()
			c, u := creates, updates
			mu.Unlock()
			hmu.Lock()
			h := handled
			hmu.Unlock()

			got, gerr := cs.CoreV1().Secrets("ns").Get(context.Background(), "tls", metav1.GetOptions{})
			require.NoError(t, gerr)
			t.Logf("HandleSecret passes=%d  ACM creates=%d  ACM in-place updates=%d", h, c, u)
			for i := 0; i < 3; i++ {
				t.Logf("  annotation acm-certificate-arn.%d = %q", i,
					got.Annotations[fmt.Sprintf("%s/acm-certificate-arn.%d", state.OperatorName, i)])
			}
			// One create per region, and no re-import once the ARNs are recorded.
			// Pre-fix the finalizer subtest saw 6 creates -- 3 orphaned ACM certs.
			require.Equal(t, 3, c, "expected exactly one create per region; extra creates orphan ACM certificates")
			require.Equal(t, 0, u, "no in-place re-import expected for an unchanged secret")
			for i := 0; i < 3; i++ {
				require.NotEmpty(t, got.Annotations[fmt.Sprintf("%s/acm-certificate-arn.%d", state.OperatorName, i)],
					"every region must record its ARN")
			}
		})
	}
}
