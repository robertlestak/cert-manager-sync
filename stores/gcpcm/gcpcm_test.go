package gcpcm

import (
	"testing"

	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	"github.com/stretchr/testify/assert"
)

func TestFromConfig(t *testing.T) {
	tests := []struct {
		name     string
		config   map[string]string
		expected GCPStore
	}{
		{
			name: "Regular certificate configuration",
			config: map[string]string{
				"project":          "test-project",
				"location":         "us-central1",
				"certificate-name": "test-cert",
				"secret-name":      "test-secret",
			},
			expected: GCPStore{
				ProjectID:       "test-project",
				Location:        "us-central1",
				CertificateName: "test-cert",
				SecretName:      "test-secret",
				OperationType:   "certificate",
				CertificateType: "root",
			},
		},
		{
			name: "Trust store configuration",
			config: map[string]string{
				"project":           "test-project",
				"location":          "us-central1",
				"operation-type":    "truststore",
				"trust-config-name": "test-trust-config",
				"certificate-type":  "intermediate",
				"secret-name":       "test-secret",
			},
			expected: GCPStore{
				ProjectID:       "test-project",
				Location:        "us-central1",
				OperationType:   "truststore",
				TrustConfigName: "test-trust-config",
				CertificateType: "intermediate",
				SecretName:      "test-secret",
			},
		},
		{
			name: "Namespaced secret name",
			config: map[string]string{
				"project":     "test-project",
				"location":    "us-central1",
				"secret-name": "test-namespace/test-secret",
			},
			expected: GCPStore{
				ProjectID:       "test-project",
				Location:        "us-central1",
				SecretName:      "test-secret",
				SecretNamespace: "test-namespace",
				OperationType:   "certificate",
				CertificateType: "root",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &GCPStore{}
			config := tlssecret.GenericSecretSyncConfig{
				Config: tt.config,
			}

			err := store.FromConfig(config)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected.ProjectID, store.ProjectID)
			assert.Equal(t, tt.expected.Location, store.Location)
			assert.Equal(t, tt.expected.CertificateName, store.CertificateName)
			assert.Equal(t, tt.expected.TrustConfigName, store.TrustConfigName)
			assert.Equal(t, tt.expected.OperationType, store.OperationType)
			assert.Equal(t, tt.expected.CertificateType, store.CertificateType)
			assert.Equal(t, tt.expected.SecretName, store.SecretName)
			assert.Equal(t, tt.expected.SecretNamespace, store.SecretNamespace)
		})
	}
}

func TestCertToTrustAnchor(t *testing.T) {
	store := &GCPStore{}
	cert := &tlssecret.Certificate{
		Certificate: []byte("test-certificate-data"),
	}

	trustAnchor := store.certToTrustAnchor(cert)
	assert.NotNil(t, trustAnchor)
	assert.Equal(t, "test-certificate-data", trustAnchor.PemCertificate)
}

func TestCertToIntermediateCA(t *testing.T) {
	store := &GCPStore{}
	cert := &tlssecret.Certificate{
		Certificate: []byte("test-certificate-data"),
	}

	intermediateCA := store.certToIntermediateCA(cert)
	assert.NotNil(t, intermediateCA)
	assert.Equal(t, "test-certificate-data", intermediateCA.PemCertificate)
}

func TestCreateTrustStore(t *testing.T) {
	tests := []struct {
		name            string
		certificateType string
		expectAnchors   bool
		expectIntermed  bool
	}{
		{
			name:            "Root certificate creates trust anchors",
			certificateType: "root",
			expectAnchors:   true,
			expectIntermed:  false,
		},
		{
			name:            "Intermediate certificate creates intermediate CAs",
			certificateType: "intermediate",
			expectAnchors:   false,
			expectIntermed:  true,
		},
		{
			name:            "Default creates trust anchors",
			certificateType: "",
			expectAnchors:   true,
			expectIntermed:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &GCPStore{
				CertificateType: tt.certificateType,
			}
			cert := &tlssecret.Certificate{
				Certificate: []byte("test-certificate-data"),
			}

			trustStore := store.createTrustStore(cert)
			assert.NotNil(t, trustStore)

			if tt.expectAnchors {
				assert.Len(t, trustStore.TrustAnchors, 1)
				assert.Equal(t, "test-certificate-data", trustStore.TrustAnchors[0].PemCertificate)
				assert.Nil(t, trustStore.IntermediateCas)
			}

			if tt.expectIntermed {
				assert.Len(t, trustStore.IntermediateCas, 1)
				assert.Equal(t, "test-certificate-data", trustStore.IntermediateCas[0].PemCertificate)
				assert.Nil(t, trustStore.TrustAnchors)
			}
		})
	}
}
