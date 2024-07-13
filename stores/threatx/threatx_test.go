package threatx

import (
	"testing"

	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
)

func TestParseCertificate(t *testing.T) {
	tests := []struct {
		name        string
		certificate *tlssecret.Certificate
		want        *ThreatXStore
	}{
		{
			name: "Test with valid annotations",
			certificate: &tlssecret.Certificate{
				Annotations: map[string]string{
					state.OperatorName + "/threatx-secret-name": "namespace/secret-name",
					state.OperatorName + "/threatx-hostname":    "test-hostname",
				},
			},
			want: &ThreatXStore{
				SecretName:      "secret-name",
				SecretNamespace: "namespace",
				Hostname:        "test-hostname",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := &ThreatXStore{}
			if err := ts.ParseCertificate(tt.certificate); err != nil {
				t.Errorf("ParseCertificate() error = %v", err)
				return
			}
			if ts.SecretName != tt.want.SecretName || ts.SecretNamespace != tt.want.SecretNamespace || ts.Hostname != tt.want.Hostname {
				t.Errorf("ParseCertificate() = %v, want %v", ts, tt.want)
			}
		})
	}
}
