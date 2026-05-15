package heroku

import (
	"context"
	"errors"
	"testing"

	heroku "github.com/heroku/heroku-go/v5"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/kubernetes/fake"
)

func TestIsHerokuNotFound(t *testing.T) {
	assert.False(t, isHerokuNotFound(nil))
	assert.False(t, isHerokuNotFound(errors.New("plain")))
	notFound := heroku.Error{StatusCode: 404}
	assert.True(t, isHerokuNotFound(notFound))
	other := heroku.Error{StatusCode: 500}
	assert.False(t, isHerokuNotFound(other))
}

func TestHerokuDelete_NoOpWhenCertNameMissing(t *testing.T) {
	// Sync never populated cert-name → no SNI endpoint exists → success.
	s := &HerokuStore{AppName: "a", SecretName: "n"}
	assert.NoError(t, s.Delete(context.Background()))
}

func TestHerokuDelete_RequiresOtherConfigWhenCertNameSet(t *testing.T) {
	cases := []struct {
		name string
		s    *HerokuStore
	}{
		{name: "missing app", s: &HerokuStore{CertName: "c", SecretName: "n"}},
		{name: "missing secret name", s: &HerokuStore{CertName: "c", AppName: "a"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.s.Delete(context.Background())
			assert.Error(t, err)
		})
	}
}

func TestHerokuSyncSecretNamespaceDefaulting(t *testing.T) {
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
			secretName:  "heroku-creds",
			wantName:    "heroku-creds",
			wantNS:      "cert-manager",
			errContains: "cert-manager/heroku-creds",
		},
		{
			name:        "preserves namespaced secret name",
			secretName:  "shared/heroku-creds",
			wantName:    "heroku-creds",
			wantNS:      "shared",
			errContains: "shared/heroku-creds",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &HerokuStore{}
			err := s.FromConfig(tlssecret.GenericSecretSyncConfig{
				Config: map[string]string{
					"secret-name": tc.secretName,
					"app":         "app",
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
