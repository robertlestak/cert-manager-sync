package digitalocean

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/digitalocean/godo"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/kubernetes/fake"
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

func TestIsDigitalOceanNotFound(t *testing.T) {
	assert.False(t, isDigitalOceanNotFound(nil, nil))
	assert.False(t, isDigitalOceanNotFound(nil, errors.New("plain")))
	resp := &godo.Response{Response: &http.Response{StatusCode: 404}}
	assert.True(t, isDigitalOceanNotFound(resp, errors.New("not found")))
	resp500 := &godo.Response{Response: &http.Response{StatusCode: 500}}
	assert.False(t, isDigitalOceanNotFound(resp500, errors.New("boom")))
}

func TestDigitalOceanDelete_NoOpWhenCertIdMissing(t *testing.T) {
	// Sync never populated cert-id → nothing was created remotely → success.
	s := &DigitalOceanStore{}
	assert.NoError(t, s.Delete(context.Background()))
}

func TestDigitalOceanDelete_RequiresSecretNameWhenCertIdSet(t *testing.T) {
	// cert-id is set but the credentials secret is missing — real config
	// problem, must surface as an error so the operator retries.
	s := &DigitalOceanStore{CertId: "abc"}
	err := s.Delete(context.Background())
	assert.Error(t, err)
}

func TestDigitalOceanSyncSecretNamespaceDefaulting(t *testing.T) {
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
			secretName:  "do-creds",
			wantName:    "do-creds",
			wantNS:      "cert-manager",
			errContains: "cert-manager/do-creds",
		},
		{
			name:        "preserves namespaced secret name",
			secretName:  "shared/do-creds",
			wantName:    "do-creds",
			wantNS:      "shared",
			errContains: "shared/do-creds",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &DigitalOceanStore{}
			err := s.FromConfig(tlssecret.GenericSecretSyncConfig{
				Config: map[string]string{"secret-name": tc.secretName},
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

func TestSeparateCertsDO(t *testing.T) {
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
			got := separateCertsDO(tt.ca, tt.crt, tt.key)
			if got == nil {
				t.Fatalf("Expected non-nil result")
			}

			// Validate the leaf certificate
			certPEM, _ := pem.Decode([]byte(got.LeafCertificate))
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
				chainPEM, _ := pem.Decode([]byte(got.CertificateChain))
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
