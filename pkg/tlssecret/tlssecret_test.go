package tlssecret

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/robertlestak/cert-manager-sync/pkg/state"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestParseSecret(t *testing.T) {
	tests := []struct {
		name   string
		secret *corev1.Secret
		want   *Certificate
	}{
		{
			name: "Test with a valid secret",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-namespace",
					Annotations: map[string]string{
						state.OperatorName + "/acm-key1": "value1",
					},
				},
				Data: map[string][]byte{
					"ca.crt":  []byte("test-ca"),
					"tls.crt": []byte("test-crt"),
					"tls.key": []byte("test-key"),
				},
			},
			want: &Certificate{
				SecretName:  "test-secret",
				Namespace:   "test-namespace",
				Ca:          []byte("test-ca"),
				Certificate: []byte("test-crt"),
				Key:         []byte("test-key"),
				Syncs: []*GenericSecretSyncConfig{
					{
						Config: map[string]string{"key1": "value1"},
						Store:  "acm",
						Index:  -1,
					},
				},
			},
		},
		{
			name: "Test with a valid secret with multiple annotations",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-namespace",
					Annotations: map[string]string{
						state.OperatorName + "/acm-key1":   "value1",
						state.OperatorName + "/acm-key2":   "value2",
						state.OperatorName + "/acm-key1.0": "value1.0",
						state.OperatorName + "/acm-key2.0": "value2.0",
					},
				},
				Data: map[string][]byte{
					"ca.crt":  []byte("test-ca"),
					"tls.crt": []byte("test-crt"),
					"tls.key": []byte("test-key"),
				},
			},
			want: &Certificate{
				SecretName:  "test-secret",
				Namespace:   "test-namespace",
				Ca:          []byte("test-ca"),
				Certificate: []byte("test-crt"),
				Key:         []byte("test-key"),
				Syncs: []*GenericSecretSyncConfig{
					{
						Config: map[string]string{"key1": "value1", "key2": "value2"},
						Store:  "acm",
						Index:  -1,
					},
					{
						Config: map[string]string{"key1": "value1.0", "key2": "value2.0"},
						Store:  "acm",
						Index:  0,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseSecret(tt.secret)

			// Compare basic fields
			if got.SecretName != tt.want.SecretName ||
				got.Namespace != tt.want.Namespace ||
				!reflect.DeepEqual(got.Ca, tt.want.Ca) ||
				!reflect.DeepEqual(got.Certificate, tt.want.Certificate) ||
				!reflect.DeepEqual(got.Key, tt.want.Key) {
				t.Errorf("ParseSecret() basic fields mismatch. got = %v, want = %v", got, tt.want)
			}

			// Compare Syncs length
			if len(got.Syncs) != len(tt.want.Syncs) {
				t.Errorf("ParseSecret() syncs length mismatch: got %d, want %d", len(got.Syncs), len(tt.want.Syncs))
				return
			}

			// Compare each sync config
			for i, wantSync := range tt.want.Syncs {
				gotSync := got.Syncs[i]
				if gotSync.Store != wantSync.Store || gotSync.Index != wantSync.Index {
					t.Errorf("ParseSecret() sync[%d] metadata mismatch: got %+v, want %+v", i, gotSync, wantSync)
				}

				// Compare configs
				if !reflect.DeepEqual(gotSync.Config, wantSync.Config) {
					t.Errorf("ParseSecret() sync[%d].Config mismatch: got %v, want %v", i, gotSync.Config, wantSync.Config)
				}
			}
		})
	}
}

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

// TestFullChain tests the FullChain method
// by creating a new key and certificate and checking
// whether this can be parsed as a certificate
// it will then try the same with a custom CA certificate

func TestFullChain(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	cert, key, err := GenerateCert(key)
	if err != nil {
		t.Fatalf("Failed to generate cert: %v", err)
	}

	ca, _, err := GenerateCert(key)
	if err != nil {
		t.Fatalf("Failed to generate CA cert: %v", err)
	}

	tests := []struct {
		name string
		cert *Certificate
		want []byte
	}{
		{
			name: "No CA",
			cert: &Certificate{
				Certificate: cert,
				Key:         key,
			},
			want: cert,
		},
		{
			name: "With CA",
			cert: &Certificate{
				Certificate: cert,
				Key:         key,
				Ca:          ca,
			},
			want: append(append(cert, '\n'), ca...),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cert.FullChain()
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Certificate.FullChain() = %v, want %v", got, tt.want)
			}

			// Validate the parsed certificate
			certPEM, _ := pem.Decode(got)
			if certPEM == nil {
				t.Errorf("Failed to decode certificate PEM block")
			}
			if certPEM == nil {
				t.Errorf("Failed to decode certificate PEM block")
			}
			_, err := x509.ParseCertificate(certPEM.Bytes)
			if err != nil {
				t.Errorf("Failed to parse certificate: %v", err)
			}
		})
	}
}
