package incapsula

import (
	"testing"

	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
)

func TestParseCertificate(t *testing.T) {
	tests := []struct {
		name        string
		certificate *tlssecret.Certificate
		want        *IncapsulaStore
	}{
		{
			name: "Test with valid annotations",
			certificate: &tlssecret.Certificate{
				Annotations: map[string]string{
					state.OperatorName + "/incapsula-site-id":     "test-site-id",
					state.OperatorName + "/incapsula-secret-name": "namespace/secret-name",
				},
			},
			want: &IncapsulaStore{
				SiteID:          "test-site-id",
				SecretName:      "secret-name",
				SecretNamespace: "namespace",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := &IncapsulaStore{}
			if err := is.ParseCertificate(tt.certificate); err != nil {
				t.Errorf("ParseCertificate() error = %v", err)
				return
			}
			if is.SiteID != tt.want.SiteID || is.SecretName != tt.want.SecretName || is.SecretNamespace != tt.want.SecretNamespace {
				t.Errorf("ParseCertificate() = %v, want %v", is, tt.want)
			}
		})
	}
}
