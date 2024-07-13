package gcpcm

import (
	"reflect"
	"testing"

	"cloud.google.com/go/certificatemanager/apiv1/certificatemanagerpb"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSecretToGCPCert(t *testing.T) {
	tests := []struct {
		name   string
		secret *corev1.Secret
		want   *certificatemanagerpb.Certificate
	}{
		{
			name: "Test with valid secret",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-name",
					Namespace: "test-namespace",
				},
				Data: map[string][]byte{
					"tls.crt": []byte("test-cert"),
					"tls.key": []byte("test-key"),
				},
			},
			want: &certificatemanagerpb.Certificate{
				Name: "projects/test-project/locations/test-location/certificates/test-namespace-test-name",
				Type: &certificatemanagerpb.Certificate_SelfManaged{
					SelfManaged: &certificatemanagerpb.Certificate_SelfManagedCertificate{
						PemCertificate: "test-cert",
						PemPrivateKey:  "test-key",
					},
				},
			},
		},
		{
			name: "Test with valid secret and ca cert",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-name",
					Namespace: "test-namespace",
				},
				Data: map[string][]byte{
					"ca.crt":  []byte("test-ca"),
					"tls.crt": []byte("test-cert"),
					"tls.key": []byte("test-key"),
				},
			},
			want: &certificatemanagerpb.Certificate{
				Name: "projects/test-project/locations/test-location/certificates/test-namespace-test-name",
				Type: &certificatemanagerpb.Certificate_SelfManaged{
					SelfManaged: &certificatemanagerpb.Certificate_SelfManagedCertificate{
						PemCertificate: "test-cert\ntest-ca",
						PemPrivateKey:  "test-key",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &GCPStore{
				ProjectID: "test-project",
				Location:  "test-location",
			}
			if got := s.secretToGCPCert(tt.secret); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("secretToGCPCert() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseCertificate(t *testing.T) {
	tests := []struct {
		name        string
		certificate *tlssecret.Certificate
		want        *GCPStore
	}{
		{
			name: "Test with valid annotations",
			certificate: &tlssecret.Certificate{
				Annotations: map[string]string{
					state.OperatorName + "/gcp-project":          "test-project",
					state.OperatorName + "/gcp-location":         "test-location",
					state.OperatorName + "/gcp-certificate-name": "test-certificate-name",
					state.OperatorName + "/gcp-secret-name":      "namespace/secret-name",
				},
			},
			want: &GCPStore{
				ProjectID:       "test-project",
				Location:        "test-location",
				CertificateName: "test-certificate-name",
				SecretName:      "secret-name",
				SecretNamespace: "namespace",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &GCPStore{}
			if err := s.ParseCertificate(tt.certificate); err != nil {
				t.Errorf("ParseCertificate() error = %v", err)
				return
			}
			if !reflect.DeepEqual(s, tt.want) {
				t.Errorf("ParseCertificate() = %v, want %v", s, tt.want)
			}
		})
	}
}
