package tlssecret

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"reflect"
	"testing"
	"time"

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
					Name:        "test-secret",
					Namespace:   "test-namespace",
					Annotations: map[string]string{"annotation-key": "annotation-value"},
					Labels:      map[string]string{"label-key": "label-value"},
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
				Annotations: map[string]string{"annotation-key": "annotation-value"},
				Labels:      map[string]string{"label-key": "label-value"},
				Ca:          []byte("test-ca"),
				Certificate: []byte("test-crt"),
				Key:         []byte("test-key"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseSecret(tt.secret); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseSecret() = %v, want %v", got, tt.want)
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

func TestCertificate_Base64Decode(t *testing.T) {
	tests := []struct {
		name    string
		cert    *Certificate
		wantErr bool
	}{
		{
			name: "All fields encoded correctly",
			cert: &Certificate{
				Ca:          []byte(base64.StdEncoding.EncodeToString([]byte("CA Data"))),
				Certificate: []byte(base64.StdEncoding.EncodeToString([]byte("Certificate Data"))),
				Key:         []byte(base64.StdEncoding.EncodeToString([]byte("Key Data"))),
			},
			wantErr: false,
		},
		{
			name: "Certificate field encoded incorrectly",
			cert: &Certificate{
				Ca:          []byte(base64.StdEncoding.EncodeToString([]byte("CA Data"))),
				Certificate: []byte("Not Base64"),
				Key:         []byte(base64.StdEncoding.EncodeToString([]byte("Key Data"))),
			},
			wantErr: true,
		},
		{
			name:    "All fields nil",
			cert:    &Certificate{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cert.Base64Decode()
			if (err != nil) != tt.wantErr {
				t.Errorf("Certificate.Base64Decode() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				// For the successful case, verify the decoded data
				if tt.name == "All fields encoded correctly" {
					if string(tt.cert.Ca) != "CA Data" || string(tt.cert.Certificate) != "Certificate Data" || string(tt.cert.Key) != "Key Data" {
						t.Errorf("Certificate.Base64Decode() did not decode correctly")
					}
				}
			}
		})
	}
}
