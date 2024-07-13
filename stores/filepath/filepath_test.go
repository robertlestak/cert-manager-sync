package filepath

import (
	"testing"

	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
)

func TestParseCertificate(t *testing.T) {
	tests := []struct {
		name        string
		certificate *tlssecret.Certificate
		want        *FilepathStore
	}{
		{
			name: "Test with valid annotations",
			certificate: &tlssecret.Certificate{
				Annotations: map[string]string{
					state.OperatorName + "/filepath-dir":  "test-dir",
					state.OperatorName + "/filepath-cert": "test-cert",
					state.OperatorName + "/filepath-key":  "test-key",
					state.OperatorName + "/filepath-ca":   "test-ca",
				},
			},
			want: &FilepathStore{
				Directory: "test-dir",
				CertFile:  "test-cert",
				KeyFile:   "test-key",
				CAFile:    "test-ca",
			},
		},
		{
			name: "Test with missing annotations",
			certificate: &tlssecret.Certificate{
				Annotations: map[string]string{
					state.OperatorName + "/filepath-dir": "test-dir",
				},
			},
			want: &FilepathStore{
				Directory: "test-dir",
				CertFile:  "tls.crt",
				KeyFile:   "tls.key",
				CAFile:    "ca.crt",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := &FilepathStore{}
			if err := fs.ParseCertificate(tt.certificate); err != nil {
				t.Errorf("ParseCertificate() error = %v", err)
				return
			}
			if fs.Directory != tt.want.Directory || fs.CertFile != tt.want.CertFile || fs.KeyFile != tt.want.KeyFile || fs.CAFile != tt.want.CAFile {
				t.Errorf("ParseCertificate() = %v, want %v", fs, tt.want)
			}
		})
	}
}
