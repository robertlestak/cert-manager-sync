package acm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
)

// GenerateKey generates an ECDSA private key.
func GenerateKey() ([]byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})
	return keyPem, nil
}

// GenerateCert generates a self-signed certificate.
func GenerateCert(key []byte) ([]byte, []byte, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode private key")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Subject:      pkix.Name{CommonName: "localhost"},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	return certPem, key, nil
}

func TestSeparateCertsACM(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	cert, _, err := GenerateCert(key)
	if err != nil {
		t.Fatalf("Failed to generate cert: %v", err)
	}

	ca, _, err := GenerateCert(key)
	if err != nil {
		t.Fatalf("Failed to generate CA cert: %v", err)
	}

	tests := []struct {
		name    string
		ca      []byte
		crt     []byte
		key     []byte
		wantErr bool
	}{
		{
			name:    "Valid certificate without CA",
			ca:      nil,
			crt:     cert,
			key:     key,
			wantErr: false,
		},
		{
			name:    "Valid certificate with CA",
			ca:      ca,
			crt:     cert,
			key:     key,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := separateCertsACM(tt.ca, tt.crt, tt.key)
			if got == nil {
				t.Fatalf("Expected non-nil result")
			}

			// Validate the leaf certificate
			certPEM, _ := pem.Decode(got.Certificate)
			if certPEM == nil {
				t.Errorf("Failed to decode certificate PEM block")
				return
			}
			_, err := x509.ParseCertificate(certPEM.Bytes)
			if err != nil {
				t.Errorf("Failed to parse certificate: %v", err)
				return
			}

			// Validate the certificate chain if CA is provided
			if len(tt.ca) > 0 {
				chainPEM, _ := pem.Decode(got.CertificateChain)
				if chainPEM == nil {
					t.Errorf("Failed to decode certificate chain PEM block")
					return
				}
				_, err := x509.ParseCertificate(chainPEM.Bytes)
				if err != nil {
					t.Errorf("Failed to parse certificate chain: %v", err)
					return
				}
			}
		})
	}
}

func TestParseCertificate(t *testing.T) {
	tests := []struct {
		name        string
		certificate *tlssecret.Certificate
		want        *ACMStore
	}{
		{
			name: "Test with valid annotations",
			certificate: &tlssecret.Certificate{
				Annotations: map[string]string{
					state.OperatorName + "/acm-role-arn":        "test-role-arn",
					state.OperatorName + "/acm-region":          "test-region",
					state.OperatorName + "/acm-certificate-arn": "test-certificate-arn",
					state.OperatorName + "/acm-secret-name":     "namespace/secret-name",
				},
			},
			want: &ACMStore{
				RoleArn:         "test-role-arn",
				Region:          "test-region",
				CertificateArn:  "test-certificate-arn",
				SecretName:      "secret-name",
				SecretNamespace: "namespace",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			as := &ACMStore{}
			if err := as.ParseCertificate(tt.certificate); err != nil {
				t.Errorf("ParseCertificate() error = %v", err)
				return
			}
			if as.RoleArn != tt.want.RoleArn || as.Region != tt.want.Region || as.CertificateArn != tt.want.CertificateArn || as.SecretName != tt.want.SecretName || as.SecretNamespace != tt.want.SecretNamespace {
				t.Errorf("ParseCertificate() = %v, want %v", as, tt.want)
			}
		})
	}
}
