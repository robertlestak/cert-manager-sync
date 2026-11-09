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

func TestReplaceCertRefs(t *testing.T) {
	cases := []struct {
		name, in, want string
		replaced       bool
	}{
		{"by name", "rpc-cert", "42", true},
		{"by id", "7", "42", true},
		{"keeps other SNI certs", "other, rpc-cert", "other,42", true},
		{"dedupes when new id already listed", "42,rpc-cert", "42", true},
		{"no match leaves annotation alone", "other", "other", false},
		{"empty", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, replaced := replaceCertRefs(tc.in, []string{"7", "rpc-cert"}, 42)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.replaced, replaced)
		})
	}
}

func TestUpdateServices(t *testing.T) {
	oldClient := state.KubeClient
	state.KubeClient = fake.NewSimpleClientset(
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{
			Name: "traefik-https", Namespace: "traefik",
			Annotations: map[string]string{ccmCertificatesAnnotation: "rpc-cert", "keep": "me"},
		}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{
			Name: "unrelated", Namespace: "traefik",
			Annotations: map[string]string{ccmCertificatesAnnotation: "someone-else"},
		}},
	)
	t.Cleanup(func() { state.KubeClient = oldClient })

	s := &HetznerCloudStore{Services: []k8stypes.NamespacedName{
		{Namespace: "traefik", Name: "traefik-https"},
		{Namespace: "traefik", Name: "unrelated"},
	}}
	assert.NoError(t, s.updateServices(context.Background(), []string{"7", "rpc-cert"}, 42))

	got, _ := state.KubeClient.CoreV1().Services("traefik").Get(context.Background(), "traefik-https", metav1.GetOptions{})
	assert.Equal(t, "42", got.Annotations[ccmCertificatesAnnotation])
	assert.Equal(t, "me", got.Annotations["keep"])

	other, _ := state.KubeClient.CoreV1().Services("traefik").Get(context.Background(), "unrelated", metav1.GetOptions{})
	assert.Equal(t, "someone-else", other.Annotations[ccmCertificatesAnnotation])

	s.Services = append(s.Services, k8stypes.NamespacedName{Namespace: "traefik", Name: "missing"})
	assert.Error(t, s.updateServices(context.Background(), []string{"7"}, 42))
}

func TestFromConfigServicesAndPending(t *testing.T) {
	s := &HetznerCloudStore{}
	err := s.FromConfig(tlssecret.GenericSecretSyncConfig{Store: "hetznercloud", Config: map[string]string{
		"services":       "traefik/traefik-https",
		"pending-delete": "11, 12,bogus",
	}})
	assert.NoError(t, err)
	assert.Equal(t, "traefik/traefik-https", s.ServicesRaw)
	assert.Equal(t, []int64{11, 12}, s.PendingDelete)
}

// TestIntegrationInUseRenewalUpdatesServices renews a certificate attached to a
// Load Balancer and checks that the referencing Service is moved to the new
// certificate and the old one is deleted once the LB releases it.
func TestIntegrationInUseRenewalUpdatesServices(t *testing.T) {
	apiToken := os.Getenv("HETZNER_TEST_TOKEN")
	if apiToken == "" {
		t.Skip("Skipping integration test: HETZNER_TEST_TOKEN not set")
	}
	oldTimeout, oldInterval := unusedPollTimeout, unusedPollInterval
	unusedPollTimeout, unusedPollInterval = 5*time.Second, time.Second
	t.Cleanup(func() { unusedPollTimeout, unusedPollInterval = oldTimeout, oldInterval })

	ctx := context.Background()
	client := hcloud.NewClient(hcloud.WithToken(apiToken))
	certName := fmt.Sprintf("cert-sync-svc-test-%d", time.Now().Unix())

	oldKube := state.KubeClient
	state.KubeClient = fake.NewSimpleClientset(&corev1.Service{ObjectMeta: metav1.ObjectMeta{
		Name: "traefik-https", Namespace: "traefik",
		Annotations: map[string]string{ccmCertificatesAnnotation: certName},
	}})
	t.Cleanup(func() { state.KubeClient = oldKube })

	cert1, key1, err := generateTestCertificate()
	assert.NoError(t, err)
	cert2, key2, err := generateTestCertificate()
	assert.NoError(t, err)

	s := &HetznerCloudStore{ApiToken: apiToken, CertName: certName, SecretName: "test-secret", ServicesRaw: "traefik/traefik-https"}
	u1, err := s.Sync(&tlssecret.Certificate{SecretName: "rpc", Namespace: "traefik", Certificate: cert1, Key: key1})
	if !assert.NoError(t, err) {
		return
	}
	oldID, _ := strconv.ParseInt(u1["cert-id"], 10, 64)

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
	var newID int64
	t.Cleanup(func() {
		_, _ = client.LoadBalancer.Delete(ctx, lb)
		for _, id := range []int64{oldID, newID} {
			if id != 0 {
				_, _ = client.Certificate.Delete(ctx, &hcloud.Certificate{ID: id})
			}
		}
	})
	_ = client.Action.WaitFor(ctx, lbRes.Action)

	// Renew while the LB still uses the old certificate. No CCM runs here, so
	// the old certificate stays attached and must end up pending deletion.
	s2 := &HetznerCloudStore{ApiToken: apiToken, CertName: certName, SecretName: "test-secret", ServicesRaw: "traefik/traefik-https", CertId: oldID}
	u2, err := s2.Sync(&tlssecret.Certificate{SecretName: "rpc", Namespace: "traefik", Certificate: cert2, Key: key2})
	if !assert.NoError(t, err) {
		return
	}
	newID, _ = strconv.ParseInt(u2["cert-id"], 10, 64)
	assert.NotEqual(t, oldID, newID)
	assert.Equal(t, strconv.FormatInt(oldID, 10), u2["pending-delete"])

	svc, _ := state.KubeClient.CoreV1().Services("traefik").Get(ctx, "traefik-https", metav1.GetOptions{})
	assert.Equal(t, strconv.FormatInt(newID, 10), svc.Annotations[ccmCertificatesAnnotation])

	// Simulate the CCM reconciling the Service onto the new certificate.
	act, _, err := client.LoadBalancer.UpdateService(ctx, lb, 443, hcloud.LoadBalancerUpdateServiceOpts{
		HTTP: &hcloud.LoadBalancerUpdateServiceOptsHTTP{Certificates: []*hcloud.Certificate{{ID: newID}}},
	})
	if !assert.NoError(t, err) {
		return
	}
	_ = client.Action.WaitFor(ctx, act)

	assert.Empty(t, cleanupPending(ctx, client, []int64{oldID}))
	gone, _, err := client.Certificate.GetByID(ctx, oldID)
	assert.NoError(t, err)
	assert.Nil(t, gone)
}
