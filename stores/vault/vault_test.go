package vault

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	"software.sslmate.com/src/go-pkcs12"
)

func TestInsertSliceString(t *testing.T) {
	tests := []struct {
		name  string
		a     []string
		index int
		value string
		want  []string
	}{
		{
			name:  "Test with empty slice",
			a:     []string{},
			index: 0,
			value: "test",
			want:  []string{"test"},
		},
		{
			name:  "Test with non-empty slice and index less than length",
			a:     []string{"value1", "value2"},
			index: 1,
			value: "test",
			want:  []string{"value1", "test", "value2"},
		},
		{
			name:  "Test with non-empty slice and index equal to length",
			a:     []string{"value1", "value2"},
			index: 2,
			value: "test",
			want:  []string{"value1", "value2", "test"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := insertSliceString(tt.a, tt.index, tt.value); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("insertSliceString() = %v, want %v", got, tt.want)
			}
		})
	}
}

// generateECCertificate generates an EC certificate and key for testing
func generateECCertificate() (cert []byte, key []byte, ca []byte, err error) {
	// Generate private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create a self-signed certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create CA certificate
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Generate CA private key
	caPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create CA certificate
	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create certificate signed by CA
	certBytes, err := x509.CreateCertificate(rand.Reader, template, caTemplate, &privateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, nil, nil, err
	}

	// Encode private key to PEM
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	// Encode CA certificate to PEM
	caPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	return certPEM, keyPEM, caPEM, nil
}

// generateRSACertificate generates an RSA certificate and key for testing
func generateRSACertificate() (cert []byte, key []byte, ca []byte, err error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create a self-signed certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create CA certificate
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Generate CA private key
	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create CA certificate
	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create certificate signed by CA
	certBytes, err := x509.CreateCertificate(rand.Reader, template, caTemplate, &privateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, nil, nil, err
	}

	// Encode private key to PEM
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	// Encode CA certificate to PEM
	caPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	return certPEM, keyPEM, caPEM, nil
}

// TestPKCS12Conversion tests the PKCS#12 conversion functionality
func TestPKCS12Conversion(t *testing.T) {
	// Test with EC certificate
	t.Run("EC Certificate", func(t *testing.T) {
		// Generate test certificate and key
		cert, key, ca, err := generateECCertificate()
		if err != nil {
			t.Fatalf("Failed to generate EC test certificate: %v", err)
		}

		// Create a VaultStore with PKCS12 enabled
		store := &VaultStore{
			PKCS12: true,
		}

		// Test with a fixed password
		t.Run("With fixed password", func(t *testing.T) {
			// Call convertToPKCS12WithPassword directly with a test password
			pkcs12Data, password, err := store.convertToPKCS12WithPassword(cert, key, ca, "test-password")
			if err != nil {
				t.Fatalf("Failed to convert to PKCS12: %v", err)
			}

			// Verify the password is what we expect
			if password != "test-password" {
				t.Errorf("Expected password 'test-password', got '%s'", password)
			}

			// Verify the PKCS12 data can be decoded
			privateKey, certificate, caCerts, err := pkcs12.DecodeChain(pkcs12Data, password)
			if err != nil {
				t.Fatalf("Failed to decode PKCS12 data: %v", err)
			}

			// Verify we got a private key
			if privateKey == nil {
				t.Error("No private key in PKCS12 data")
			}

			// Verify we got a certificate
			if certificate == nil {
				t.Error("No certificate in PKCS12 data")
			}

			// Verify we got CA certificates
			if len(caCerts) == 0 {
				t.Error("No CA certificates in PKCS12 data")
			}
			
			// Verify the private key type
			_, ok := privateKey.(*ecdsa.PrivateKey)
			if !ok {
				t.Error("Private key is not an EC key")
			}
		})

		// Test with a random password
		t.Run("With random password", func(t *testing.T) {
			// Call convertToPKCS12WithPassword directly with an empty password to trigger random generation
			pkcs12Data, password, err := store.convertToPKCS12WithPassword(cert, key, ca, "")
			if err != nil {
				t.Fatalf("Failed to convert to PKCS12: %v", err)
			}

			// Verify a random password was generated
			if password == "" {
				t.Error("No random password was generated")
			}

			// Verify the PKCS12 data can be decoded with the generated password
			privateKey, certificate, caCerts, err := pkcs12.DecodeChain(pkcs12Data, password)
			if err != nil {
				t.Fatalf("Failed to decode PKCS12 data: %v", err)
			}

			// Verify we got a private key
			if privateKey == nil {
				t.Error("No private key in PKCS12 data")
			}

			// Verify we got a certificate
			if certificate == nil {
				t.Error("No certificate in PKCS12 data")
			}

			// Verify we got CA certificates
			if len(caCerts) == 0 {
				t.Error("No CA certificates in PKCS12 data")
			}
		})
	})
	
	// Test with RSA certificate
	t.Run("RSA Certificate", func(t *testing.T) {
		// Generate test certificate and key
		cert, key, ca, err := generateRSACertificate()
		if err != nil {
			t.Fatalf("Failed to generate RSA test certificate: %v", err)
		}

		// Create a VaultStore with PKCS12 enabled
		store := &VaultStore{
			PKCS12: true,
		}

		// Test with a fixed password
		t.Run("With fixed password", func(t *testing.T) {
			// Call convertToPKCS12WithPassword directly with a test password
			pkcs12Data, password, err := store.convertToPKCS12WithPassword(cert, key, ca, "test-password")
			if err != nil {
				t.Fatalf("Failed to convert to PKCS12: %v", err)
			}

			// Verify the password is what we expect
			if password != "test-password" {
				t.Errorf("Expected password 'test-password', got '%s'", password)
			}

			// Verify the PKCS12 data can be decoded
			privateKey, certificate, caCerts, err := pkcs12.DecodeChain(pkcs12Data, password)
			if err != nil {
				t.Fatalf("Failed to decode PKCS12 data: %v", err)
			}

			// Verify we got a private key
			if privateKey == nil {
				t.Error("No private key in PKCS12 data")
			}

			// Verify we got a certificate
			if certificate == nil {
				t.Error("No certificate in PKCS12 data")
			}

			// Verify we got CA certificates
			if len(caCerts) == 0 {
				t.Error("No CA certificates in PKCS12 data")
			}
			
			// Verify the private key type
			_, ok := privateKey.(*rsa.PrivateKey)
			if !ok {
				t.Error("Private key is not an RSA key")
			}
		})
	})
	
	// Test with certificate but no CA
	t.Run("Certificate without CA", func(t *testing.T) {
		// Generate test certificate and key
		cert, key, _, err := generateECCertificate()
		if err != nil {
			t.Fatalf("Failed to generate test certificate: %v", err)
		}

		// Create a VaultStore with PKCS12 enabled
		store := &VaultStore{
			PKCS12: true,
		}

		// Call convertToPKCS12WithPassword with no CA
		pkcs12Data, password, err := store.convertToPKCS12WithPassword(cert, key, nil, "test-password")
		if err != nil {
			t.Fatalf("Failed to convert to PKCS12: %v", err)
		}

		// Verify the PKCS12 data can be decoded
		privateKey, certificate, caCerts, err := pkcs12.DecodeChain(pkcs12Data, password)
		if err != nil {
			t.Fatalf("Failed to decode PKCS12 data: %v", err)
		}

		// Verify we got a private key
		if privateKey == nil {
			t.Error("No private key in PKCS12 data")
		}

		// Verify we got a certificate
		if certificate == nil {
			t.Error("No certificate in PKCS12 data")
		}

		// Verify we got no CA certificates
		if len(caCerts) != 0 {
			t.Error("Expected no CA certificates in PKCS12 data")
		}
	})
}

// TestFromConfig tests the FromConfig method
func TestFromConfig(t *testing.T) {
	tests := []struct {
		name   string
		config map[string]string
		want   VaultStore
	}{
		{
			name: "Basic config",
			config: map[string]string{
				"path":        "secret/data/test",
				"addr":        "https://vault.example.com",
				"namespace":   "ns1",
				"role":        "role1",
				"auth-method": "kubernetes",
			},
			want: VaultStore{
				Path:      "secret/data/test",
				Addr:      "https://vault.example.com",
				Namespace: "ns1",
				Role:      "role1",
				AuthMethod: "kubernetes",
			},
		},
		{
			name: "With base64 decode",
			config: map[string]string{
				"path":         "secret/data/test",
				"base64-decode": "true",
			},
			want: VaultStore{
				Path:        "secret/data/test",
				Base64Decode: true,
			},
		},
		{
			name: "With PKCS12 enabled",
			config: map[string]string{
				"path":    "secret/data/test",
				"pkcs12":  "true",
			},
			want: VaultStore{
				Path:   "secret/data/test",
				PKCS12: true,
			},
		},
		{
			name: "With PKCS12 password secret",
			config: map[string]string{
				"path":                   "secret/data/test",
				"pkcs12":                 "true",
				"pkcs12-password-secret": "my-secret",
			},
			want: VaultStore{
				Path:             "secret/data/test",
				PKCS12:           true,
				PKCS12PassSecret: "my-secret",
				PKCS12PassSecretKey: "password", // Default value
			},
		},
		{
			name: "With PKCS12 password secret and custom key",
			config: map[string]string{
				"path":                       "secret/data/test",
				"pkcs12":                     "true",
				"pkcs12-password-secret":     "my-secret",
				"pkcs12-password-secret-key": "my-key",
			},
			want: VaultStore{
				Path:                "secret/data/test",
				PKCS12:              true,
				PKCS12PassSecret:    "my-secret",
				PKCS12PassSecretKey: "my-key",
			},
		},
		{
			name: "With PKCS12 password secret and namespace",
			config: map[string]string{
				"path":                           "secret/data/test",
				"pkcs12":                         "true",
				"pkcs12-password-secret":         "my-secret",
				"pkcs12-password-secret-namespace": "my-namespace",
			},
			want: VaultStore{
				Path:                      "secret/data/test",
				PKCS12:                    true,
				PKCS12PassSecret:          "my-secret",
				PKCS12PassSecretKey:       "password", // Default value
				PKCS12PassSecretNamespace: "my-namespace",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &VaultStore{}
			config := tlssecret.GenericSecretSyncConfig{
				Config: tt.config,
			}
			err := store.FromConfig(config)
			if err != nil {
				t.Fatalf("FromConfig() error = %v", err)
			}
			
			// Check Path
			if store.Path != tt.want.Path {
				t.Errorf("Path = %v, want %v", store.Path, tt.want.Path)
			}
			
			// Check Addr
			if store.Addr != tt.want.Addr {
				t.Errorf("Addr = %v, want %v", store.Addr, tt.want.Addr)
			}
			
			// Check Namespace
			if store.Namespace != tt.want.Namespace {
				t.Errorf("Namespace = %v, want %v", store.Namespace, tt.want.Namespace)
			}
			
			// Check Role
			if store.Role != tt.want.Role {
				t.Errorf("Role = %v, want %v", store.Role, tt.want.Role)
			}
			
			// Check AuthMethod
			if store.AuthMethod != tt.want.AuthMethod {
				t.Errorf("AuthMethod = %v, want %v", store.AuthMethod, tt.want.AuthMethod)
			}
			
			// Check Base64Decode
			if store.Base64Decode != tt.want.Base64Decode {
				t.Errorf("Base64Decode = %v, want %v", store.Base64Decode, tt.want.Base64Decode)
			}
			
			// Check PKCS12
			if store.PKCS12 != tt.want.PKCS12 {
				t.Errorf("PKCS12 = %v, want %v", store.PKCS12, tt.want.PKCS12)
			}
			
			// Check PKCS12PassSecret
			if store.PKCS12PassSecret != tt.want.PKCS12PassSecret {
				t.Errorf("PKCS12PassSecret = %v, want %v", store.PKCS12PassSecret, tt.want.PKCS12PassSecret)
			}
			
			// Check PKCS12PassSecretKey
			if store.PKCS12PassSecretKey != tt.want.PKCS12PassSecretKey {
				t.Errorf("PKCS12PassSecretKey = %v, want %v", store.PKCS12PassSecretKey, tt.want.PKCS12PassSecretKey)
			}
			
			// Check PKCS12PassSecretNamespace
			if store.PKCS12PassSecretNamespace != tt.want.PKCS12PassSecretNamespace {
				t.Errorf("PKCS12PassSecretNamespace = %v, want %v", store.PKCS12PassSecretNamespace, tt.want.PKCS12PassSecretNamespace)
			}
		})
	}
}

// TestWriteSecretValue tests the writeSecretValue function
func TestWriteSecretValue(t *testing.T) {
	tests := []struct {
		name     string
		value    []byte
		asString bool
		wantType string
	}{
		{
			name:     "As bytes",
			value:    []byte("test"),
			asString: false,
			wantType: "[]uint8",
		},
		{
			name:     "As string",
			value:    []byte("test"),
			asString: true,
			wantType: "string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := writeSecretValue(tt.value, tt.asString)
			gotType := reflect.TypeOf(got).String()
			
			if gotType != tt.wantType {
				t.Errorf("writeSecretValue() type = %v, want %v", gotType, tt.wantType)
			}
			
			// Check value
			if tt.asString {
				if got.(string) != string(tt.value) {
					t.Errorf("writeSecretValue() = %v, want %v", got, string(tt.value))
				}
			} else {
				if !reflect.DeepEqual(got, tt.value) {
					t.Errorf("writeSecretValue() = %v, want %v", got, tt.value)
				}
			}
		})
	}
}
