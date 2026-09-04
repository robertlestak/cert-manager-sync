package cloudflare

import (
	"context"
	"errors"
	"testing"

	"github.com/cloudflare/cloudflare-go/v5"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/kubernetes/fake"
)

func TestIsCloudflareNotFound(t *testing.T) {
	assert.False(t, isCloudflareNotFound(nil))
	assert.False(t, isCloudflareNotFound(errors.New("plain")))
	cfErr := &cloudflare.Error{StatusCode: 404}
	assert.True(t, isCloudflareNotFound(cfErr))
	other := &cloudflare.Error{StatusCode: 500}
	assert.False(t, isCloudflareNotFound(other))
}

func TestCloudflareDelete_NoOpWhenCertIdMissing(t *testing.T) {
	// Sync never populated cert-id → nothing was created → success.
	s := &CloudflareStore{ZoneId: "z", SecretName: "n"}
	assert.NoError(t, s.Delete(context.Background()))
}

func TestCloudflareDelete_RequiresOtherConfigWhenCertIdSet(t *testing.T) {
	// cert-id is set (Sync did succeed at some point), but other required
	// config has been removed. We must surface this as an error so the user
	// notices and either restores config or switches to retain.
	cases := []struct {
		name string
		s    *CloudflareStore
	}{
		{name: "missing zone id", s: &CloudflareStore{CertId: "c", SecretName: "n"}},
		{name: "missing secret name", s: &CloudflareStore{CertId: "c", ZoneId: "z"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.s.Delete(context.Background())
			assert.Error(t, err)
		})
	}
}

func TestCloudflareFromConfigParsesNamespacedSecretName(t *testing.T) {
	s := &CloudflareStore{}

	err := s.FromConfig(tlssecret.GenericSecretSyncConfig{
		Config: map[string]string{
			"secret-name": "istio-system/cloudflare-poc",
			"zone-id":     "zone",
			"cert-id":     "cert",
		},
	})

	assert.NoError(t, err)
	assert.Equal(t, "cloudflare-poc", s.SecretName)
	assert.Equal(t, "istio-system", s.SecretNamespace)
	assert.Equal(t, "zone", s.ZoneId)
	assert.Equal(t, "cert", s.CertId)
}

func TestCloudflareFromConfigParsesLeafOnly(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		want    bool
		wantErr bool
	}{
		{name: "true", value: "true", want: true},
		{name: "false", value: "false", want: false},
		{name: "unset defaults to false", value: "", want: false},
		{name: "invalid value errors", value: "yes", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &CloudflareStore{}
			cfg := map[string]string{"zone-id": "zone"}
			if tc.value != "" {
				cfg["leaf-only"] = tc.value
			}
			err := s.FromConfig(tlssecret.GenericSecretSyncConfig{Config: cfg})
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.want, s.LeafOnly)
		})
	}
}

func TestCloudflareCertificatePayload(t *testing.T) {
	cert := &tlssecret.Certificate{
		Certificate: []byte("leaf"),
		Ca:          []byte("ca"),
	}

	t.Run("full chain by default", func(t *testing.T) {
		s := &CloudflareStore{}
		assert.Equal(t, cert.FullChain(), s.certificatePayload(cert))
		assert.Contains(t, string(s.certificatePayload(cert)), "ca")
	})

	t.Run("leaf only when enabled", func(t *testing.T) {
		s := &CloudflareStore{LeafOnly: true}
		assert.Equal(t, cert.Certificate, s.certificatePayload(cert))
		assert.NotContains(t, string(s.certificatePayload(cert)), "ca")
	})
}

func TestCloudflareSetDefaultSecretNamespace(t *testing.T) {
	t.Run("defaults when empty", func(t *testing.T) {
		s := &CloudflareStore{}

		s.setDefaultSecretNamespace("cert-manager")

		assert.Equal(t, "cert-manager", s.SecretNamespace)
	})

	t.Run("preserves configured namespace", func(t *testing.T) {
		s := &CloudflareStore{SecretNamespace: "istio-system"}

		s.setDefaultSecretNamespace("cert-manager")

		assert.Equal(t, "istio-system", s.SecretNamespace)
	})
}

func TestCloudflareSyncSecretNamespaceDefaulting(t *testing.T) {
	oldClient := state.KubeClient
	state.KubeClient = fake.NewSimpleClientset()
	t.Cleanup(func() { state.KubeClient = oldClient })

	cases := []struct {
		name        string
		secretName  string
		wantName    string
		wantNS      string
		errContains string
	}{
		{
			name:        "defaults plain secret name",
			secretName:  "cloudflare-poc",
			wantName:    "cloudflare-poc",
			wantNS:      "cert-manager",
			errContains: "cert-manager/cloudflare-poc",
		},
		{
			name:        "preserves namespaced secret name",
			secretName:  "istio-system/cloudflare-poc",
			wantName:    "cloudflare-poc",
			wantNS:      "istio-system",
			errContains: "istio-system/cloudflare-poc",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &CloudflareStore{}
			err := s.FromConfig(tlssecret.GenericSecretSyncConfig{
				Config: map[string]string{
					"secret-name": tc.secretName,
					"zone-id":     "zone",
				},
			})
			assert.NoError(t, err)

			_, err = s.Sync(&tlssecret.Certificate{
				SecretName: "source",
				Namespace:  "cert-manager",
			})

			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.errContains)
			assert.Equal(t, tc.wantName, s.SecretName)
			assert.Equal(t, tc.wantNS, s.SecretNamespace)
		})
	}
}
