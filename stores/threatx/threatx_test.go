package threatx

import (
	"testing"

	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/kubernetes/fake"
)

func TestThreatXSyncSecretNamespaceDefaulting(t *testing.T) {
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
			secretName:  "threatx-creds",
			wantName:    "threatx-creds",
			wantNS:      "cert-manager",
			errContains: "cert-manager/threatx-creds",
		},
		{
			name:        "preserves namespaced secret name",
			secretName:  "shared/threatx-creds",
			wantName:    "threatx-creds",
			wantNS:      "shared",
			errContains: "shared/threatx-creds",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &ThreatXStore{}
			err := s.FromConfig(tlssecret.GenericSecretSyncConfig{
				Config: map[string]string{
					"secret-name": tc.secretName,
					"hostname":    "example.com",
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
