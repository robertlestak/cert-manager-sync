package heroku

import (
	"testing"

	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
)

func TestParseCertificate(t *testing.T) {
	tests := []struct {
		name        string
		certificate *tlssecret.Certificate
		want        *HerokuStore
	}{
		{
			name: "Test with valid annotations",
			certificate: &tlssecret.Certificate{
				Annotations: map[string]string{
					state.OperatorName + "/heroku-secret-name": "namespace/secret-name",
					state.OperatorName + "/heroku-app":         "test-app",
					state.OperatorName + "/heroku-cert-name":   "test-cert-name",
				},
			},
			want: &HerokuStore{
				SecretName:      "secret-name",
				SecretNamespace: "namespace",
				AppName:         "test-app",
				CertName:        "test-cert-name",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hs := &HerokuStore{}
			if err := hs.ParseCertificate(tt.certificate); err != nil {
				t.Errorf("ParseCertificate() error = %v", err)
				return
			}
			if hs.SecretName != tt.want.SecretName || hs.SecretNamespace != tt.want.SecretNamespace || hs.AppName != tt.want.AppName || hs.CertName != tt.want.CertName {
				t.Errorf("ParseCertificate() = %v, want %v", hs, tt.want)
			}
		})
	}
}
