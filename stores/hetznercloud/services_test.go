package hetznercloud

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func TestParseServiceRefs(t *testing.T) {
	refs, err := parseServiceRefs(" traefik/traefik-https , web ,", "default")
	assert.NoError(t, err)
	assert.Equal(t, []k8stypes.NamespacedName{
		{Namespace: "traefik", Name: "traefik-https"},
		{Namespace: "default", Name: "web"},
	}, refs)

	_, err = parseServiceRefs("a/b/c", "default")
	assert.Error(t, err)
	_, err = parseServiceRefs("/name", "default")
	assert.Error(t, err)
}

func TestPointCertRefs(t *testing.T) {
	stale := []string{"7", "rpc-cert"}
	cases := []struct{ name, in, want string }{
		{"first attach", "", "42"},
		{"renewal by name", "rpc-cert", "42"},
		{"renewal by id", "7", "42"},
		{"keeps unrelated SNI certs", "other, rpc-cert", "other,42"},
		{"adds to unrelated certs", "other", "other,42"},
		{"no duplicate", "42,rpc-cert", "42"},
		{"already current", "42", "42"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, pointCertRefs(tc.in, stale, 42))
		})
	}
}

func TestOwnerValue(t *testing.T) {
	a := ownerValue("traefik", "rpc-tls", "rpc")
	assert.Len(t, a, 40)
	assert.Equal(t, a, ownerValue("traefik", "rpc-tls", "rpc"))
	assert.NotEqual(t, a, ownerValue("traefik", "rpc-tls", "rpc2"))
	assert.NotEqual(t, a, ownerValue("other", "rpc-tls", "rpc"))
}

func TestEnsureServices(t *testing.T) {
	oldClient := state.KubeClient
	state.KubeClient = fake.NewSimpleClientset(
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "fresh", Namespace: "traefik"}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{
			Name: "renewed", Namespace: "traefik",
			Annotations: map[string]string{ccmCertificatesAnnotation: "other,rpc-cert", "keep": "me"},
		}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{
			Name: "current", Namespace: "traefik", ResourceVersion: "5",
			Annotations: map[string]string{ccmCertificatesAnnotation: "42"},
		}},
	)
	t.Cleanup(func() { state.KubeClient = oldClient })

	s := &HetznerCloudStore{Services: []k8stypes.NamespacedName{
		{Namespace: "traefik", Name: "fresh"},
		{Namespace: "traefik", Name: "renewed"},
		{Namespace: "traefik", Name: "current"},
	}}
	assert.NoError(t, s.ensureServices(context.Background(), []string{"7", "rpc-cert"}, 42))

	get := func(name string) *corev1.Service {
		svc, err := state.KubeClient.CoreV1().Services("traefik").Get(context.Background(), name, metav1.GetOptions{})
		assert.NoError(t, err)
		return svc
	}
	assert.Equal(t, "42", get("fresh").Annotations[ccmCertificatesAnnotation])
	renewed := get("renewed")
	assert.Equal(t, "other,42", renewed.Annotations[ccmCertificatesAnnotation])
	assert.Equal(t, "me", renewed.Annotations["keep"])
	assert.Equal(t, "5", get("current").ResourceVersion, "up-to-date service must not be patched")

	s.Services = []k8stypes.NamespacedName{{Namespace: "traefik", Name: "missing"}}
	assert.Error(t, s.ensureServices(context.Background(), nil, 42))
}

func integrationClient(t *testing.T) (*hcloud.Client, string) {
	t.Helper()
	apiToken := os.Getenv("HETZNER_TEST_TOKEN")
	if apiToken == "" {
		t.Skip("Skipping integration test: HETZNER_TEST_TOKEN not set")
	}
	oldTimeout, oldInterval := detachRetryTimeout, detachRetryInterval
	detachRetryTimeout, detachRetryInterval = 30*time.Second, time.Second
	t.Cleanup(func() { detachRetryTimeout, detachRetryInterval = oldTimeout, oldInterval })
	return hcloud.NewClient(hcloud.WithToken(apiToken)), apiToken
}

func deleteOwned(client *hcloud.Client, owner string) {
	certs, _ := ownedCertificates(context.Background(), client, owner)
	for _, c := range certs {
		_, _ = client.Certificate.Delete(context.Background(), c)
	}
}

// TestIntegrationInUseRenewalMovesServices renews a certificate attached to a
// Load Balancer: the Service must move to the new certificate without the sync
// blocking, and the old certificate must be deleted once the LB releases it.
func TestIntegrationInUseRenewalMovesServices(t *testing.T) {
	client, apiToken := integrationClient(t)
	ctx := context.Background()
	certName := fmt.Sprintf("cert-sync-svc-test-%d", time.Now().UnixNano())
	owner := ownerValue("traefik", "rpc", certName)
	t.Cleanup(func() { deleteOwned(client, owner) })

	oldKube := state.KubeClient
	state.KubeClient = fake.NewSimpleClientset(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "traefik-https", Namespace: "traefik"}})
	t.Cleanup(func() { state.KubeClient = oldKube })
	svcAnnotation := func() string {
		svc, _ := state.KubeClient.CoreV1().Services("traefik").Get(ctx, "traefik-https", metav1.GetOptions{})
		return svc.Annotations[ccmCertificatesAnnotation]
	}

	cert1, key1, _ := generateTestCertificate()
	cert2, key2, _ := generateTestCertificate()

	s1 := &HetznerCloudStore{ApiToken: apiToken, CertName: certName, ServicesRaw: "traefik/traefik-https"}
	u1, err := s1.Sync(&tlssecret.Certificate{SecretName: "rpc", Namespace: "traefik", Certificate: cert1, Key: key1})
	if !assert.NoError(t, err) {
		return
	}
	oldID, _ := strconv.ParseInt(u1["cert-id"], 10, 64)
	assert.Equal(t, u1["cert-id"], svcAnnotation(), "first sync must attach the certificate to the service")

	intPtr := func(i int) *int { return &i }
	lbRes, _, err := client.LoadBalancer.Create(ctx, hcloud.LoadBalancerCreateOpts{
		Name:             certName,
		LoadBalancerType: &hcloud.LoadBalancerType{Name: "lb11"},
		Location:         &hcloud.Location{Name: "nbg1"},
		Services: []hcloud.LoadBalancerCreateOptsService{{
			Protocol: hcloud.LoadBalancerServiceProtocolHTTPS, ListenPort: intPtr(443), DestinationPort: intPtr(80),
			HTTP: &hcloud.LoadBalancerCreateOptsServiceHTTP{Certificates: []*hcloud.Certificate{{ID: oldID}}},
		}},
	})
	if !assert.NoError(t, err) {
		return
	}
	lb := lbRes.LoadBalancer
	t.Cleanup(func() { _, _ = client.LoadBalancer.Delete(ctx, lb) })
	_ = client.Action.WaitFor(ctx, lbRes.Action)

	start := time.Now()
	s2 := &HetznerCloudStore{ApiToken: apiToken, CertName: certName, ServicesRaw: "traefik/traefik-https", CertId: oldID}
	u2, err := s2.Sync(&tlssecret.Certificate{SecretName: "rpc", Namespace: "traefik", Certificate: cert2, Key: key2})
	if !assert.NoError(t, err) {
		return
	}
	assert.Less(t, time.Since(start), 10*time.Second, "sync must not wait for the LB to release the old certificate")
	newID, _ := strconv.ParseInt(u2["cert-id"], 10, 64)
	assert.NotEqual(t, oldID, newID)
	assert.Equal(t, u2["cert-id"], svcAnnotation())

	newCert, _, _ := client.Certificate.GetByID(ctx, newID)
	if assert.NotNil(t, newCert) {
		assert.Equal(t, fmt.Sprintf("%s-%d", certName, oldID), newCert.Name)
		assert.Equal(t, owner, newCert.Labels[ownerLabel])
	}

	// Act as the CCM: move the LB to the new certificate. The background
	// cleanup started by the sync should then delete the old one.
	act, _, err := client.LoadBalancer.UpdateService(ctx, lb, 443, hcloud.LoadBalancerUpdateServiceOpts{
		HTTP: &hcloud.LoadBalancerUpdateServiceOptsHTTP{Certificates: []*hcloud.Certificate{{ID: newID}}},
	})
	if !assert.NoError(t, err) {
		return
	}
	_ = client.Action.WaitFor(ctx, act)
	backgroundCleanups.Wait()

	gone, _, err := client.Certificate.GetByID(ctx, oldID)
	assert.NoError(t, err)
	assert.Nil(t, gone, "old certificate should be deleted once detached")
}

// TestIntegrationSyncCleansOrphans simulates certificates left behind by an
// interrupted sync (uploaded, but cert-id never recorded on the secret): the
// next sync must delete them and keep only the new certificate.
func TestIntegrationSyncCleansOrphans(t *testing.T) {
	client, apiToken := integrationClient(t)
	ctx := context.Background()
	certName := fmt.Sprintf("cert-sync-orphan-test-%d", time.Now().UnixNano())
	owner := ownerValue("traefik", "rpc", certName)
	t.Cleanup(func() { deleteOwned(client, owner) })

	for i := 0; i < 2; i++ {
		pem, key, _ := generateTestCertificate()
		_, _, err := client.Certificate.Create(ctx, hcloud.CertificateCreateOpts{
			Name: fmt.Sprintf("%s-orphan-%d", certName, i), Type: hcloud.CertificateTypeUploaded,
			Certificate: string(pem), PrivateKey: string(key), Labels: map[string]string{ownerLabel: owner},
		})
		if !assert.NoError(t, err) {
			return
		}
	}

	pem, key, _ := generateTestCertificate()
	s := &HetznerCloudStore{ApiToken: apiToken, CertName: certName}
	u, err := s.Sync(&tlssecret.Certificate{SecretName: "rpc", Namespace: "traefik", Certificate: pem, Key: key})
	if !assert.NoError(t, err) {
		return
	}
	backgroundCleanups.Wait()

	owned, err := ownedCertificates(ctx, client, owner)
	assert.NoError(t, err)
	if assert.Len(t, owned, 1) {
		assert.Equal(t, u["cert-id"], strconv.FormatInt(owned[0].ID, 10))
		assert.Equal(t, certName, owned[0].Name)
	}
}
