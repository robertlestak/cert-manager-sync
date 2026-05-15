package imperva

import (
	"testing"

	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/kubernetes/fake"
)

func TestImpervaSyncSecretNamespaceDefaulting(t *testing.T) {
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
			secretName:  "imperva-creds",
			wantName:    "imperva-creds",
			wantNS:      "cert-manager",
			errContains: "cert-manager/imperva-creds",
		},
		{
			name:        "preserves namespaced secret name",
			secretName:  "shared/imperva-creds",
			wantName:    "imperva-creds",
			wantNS:      "shared",
			errContains: "shared/imperva-creds",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &ImpervaStore{}
			err := s.FromConfig(tlssecret.GenericSecretSyncConfig{
				Config: map[string]string{
					"secret-name": tc.secretName,
					"site-id":     "site",
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
