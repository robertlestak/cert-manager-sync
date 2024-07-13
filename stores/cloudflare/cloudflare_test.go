package cloudflare

import (
	"testing"

	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
)

func TestParseCertificate(t *testing.T) {
	tests := []struct {
		name        string
		certificate *tlssecret.Certificate
		want        *CloudflareStore
	}{
		{
			name: "Test with valid annotations",
			certificate: &tlssecret.Certificate{
				Annotations: map[string]string{
					state.OperatorName + "/cloudflare-secret-name": "namespace/secret-name",
					state.OperatorName + "/cloudflare-zone-id":     "test-zone-id",
					state.OperatorName + "/cloudflare-cert-id":     "test-cert-id",
				},
			},
			want: &CloudflareStore{
				SecretName:      "secret-name",
				SecretNamespace: "namespace",
				ZoneId:          "test-zone-id",
				CertId:          "test-cert-id",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := &CloudflareStore{}
			if err := cs.ParseCertificate(tt.certificate); err != nil {
				t.Errorf("ParseCertificate() error = %v", err)
				return
			}
			if cs.SecretName != tt.want.SecretName || cs.SecretNamespace != tt.want.SecretNamespace || cs.ZoneId != tt.want.ZoneId || cs.CertId != tt.want.CertId {
				t.Errorf("ParseCertificate() = %v, want %v", cs, tt.want)
			}
		})
	}
}
