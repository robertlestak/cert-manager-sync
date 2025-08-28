package hetznercloud

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
)

// generateTestCertificate generates a valid self-signed certificate for testing
func generateTestCertificate() (cert []byte, key []byte, error error) {
	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test Org"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	// PEM encode certificate
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	// PEM encode private key
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return certPEM, keyPEM, nil
}

// TestIntegrationSync tests the full sync process with a real Hetzner Cloud API
// This test is skipped by default and only runs when HETZNER_TEST_TOKEN is set
func TestIntegrationSync(t *testing.T) {
	apiToken := os.Getenv("HETZNER_TEST_TOKEN")
	if apiToken == "" {
		t.Skip("Skipping integration test: HETZNER_TEST_TOKEN not set")
	}

	// Generate valid test certificate
	testCert, testKey, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Create store with API token
	s := &HetznerCloudStore{
		ApiToken:   apiToken,
		CertName:   fmt.Sprintf("cert-manager-sync-test-%d", time.Now().Unix()),
		SecretName: "test-secret", // Required by Sync method even though we're not using K8s
	}

	// Create certificate object
	c := &tlssecret.Certificate{
		SecretName:  "test-cert",
		Namespace:   "test",
		Certificate: testCert,
		Key:         testKey,
	}

	// Sync certificate
	updates, err := s.Sync(c)
	if err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	// Verify cert-id was returned
	if updates["cert-id"] == "" {
		t.Error("Expected cert-id in updates")
	}

	t.Logf("Successfully synced certificate with ID: %s", updates["cert-id"])

	// Clean up the test certificate
	if updates["cert-id"] != "" {
		certId, err := strconv.ParseInt(updates["cert-id"], 10, 64)
		if err != nil {
			t.Logf("Warning: Failed to parse cert ID for cleanup: %v", err)
		} else {
			// Create client for cleanup
			client := hcloud.NewClient(hcloud.WithToken(apiToken))
			ctx := context.Background()

			cert, _, err := client.Certificate.GetByID(ctx, certId)
			if err != nil {
				t.Logf("Warning: Failed to get certificate for cleanup: %v", err)
			} else if cert != nil {
				_, err = client.Certificate.Delete(ctx, cert)
				if err != nil {
					t.Logf("Warning: Failed to delete test certificate %d: %v", certId, err)
				} else {
					t.Logf("Cleaned up test certificate with ID: %d", certId)
				}
			}
		}
	}
}
