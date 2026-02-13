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
	"net"
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

// TestIntegrationSyncWithLabels tests the full sync process with labels using a real Hetzner Cloud API
// This test is skipped by default and only runs when HETZNER_TEST_TOKEN is set
func TestIntegrationSyncWithLabels(t *testing.T) {
	apiToken := os.Getenv("HETZNER_TEST_TOKEN")
	if apiToken == "" {
		t.Skip("Skipping integration test: HETZNER_TEST_TOKEN not set")
	}

	// Generate valid test certificate
	testCert, testKey, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Test various label scenarios
	testCases := []struct {
		name   string
		labels map[string]string
		valid  bool
	}{
		{
			name: "valid_labels",
			labels: map[string]string{
				"environment": "test",
				"managed-by":  "cert-manager-sync",
				"version":     "v1.2.3",
			},
			valid: true,
		},
		{
			name: "kubernetes_style_labels",
			labels: map[string]string{
				"app.kubernetes.io/name":       "cert-sync",
				"app.kubernetes.io/instance":   "production",
				"app.kubernetes.io/component":  "certificate",
				"cert-manager.io/issuer-name":  "letsencrypt",
			},
			valid: true,
		},
		{
			name: "label_with_underscore",
			labels: map[string]string{
				"test_label": "value",
			},
			valid: true,
		},
		{
			name: "empty_label_value",
			labels: map[string]string{
				"empty": "",
			},
			valid: true,
		},
		{
			name: "long_label_key",
			labels: map[string]string{
				"this-is-a-very-long-label-key-that-might-exceed-limits": "value",
			},
			valid: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create store with API token and labels
			s := &HetznerCloudStore{
				ApiToken:   apiToken,
				CertName:   fmt.Sprintf("cert-sync-test-labels-%d", time.Now().Unix()),
				SecretName: "test-secret",
				Labels:     tc.labels,
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
			if tc.valid && err != nil {
				t.Fatalf("Expected successful sync with labels %v, but got error: %v", tc.labels, err)
			}
			if !tc.valid && err == nil {
				t.Fatalf("Expected error for invalid labels %v, but sync succeeded", tc.labels)
			}

			// Clean up if certificate was created
			if updates["cert-id"] != "" {
				certId, err := strconv.ParseInt(updates["cert-id"], 10, 64)
				if err == nil {
					client := hcloud.NewClient(hcloud.WithToken(apiToken))
					ctx := context.Background()
					cert, _, err := client.Certificate.GetByID(ctx, certId)
					if err == nil && cert != nil {
						// Verify labels were applied correctly
						if tc.valid {
							// Check that we have the expected number of labels
							if len(cert.Labels) != len(tc.labels) {
								t.Errorf("Label count mismatch: expected %d labels, got %d", len(tc.labels), len(cert.Labels))
								t.Errorf("Expected labels: %v", tc.labels)
								t.Errorf("Actual labels: %v", cert.Labels)
							}
							
							// Check each expected label
							for k, v := range tc.labels {
								if cert.Labels[k] != v {
									t.Errorf("Label mismatch for key %s: expected %s, got %s", k, v, cert.Labels[k])
								}
							}
							
							// Log successful label verification
							t.Logf("Labels verified successfully on certificate %d: %v", certId, cert.Labels)
						}
						// Clean up
						_, _ = client.Certificate.Delete(ctx, cert)
						t.Logf("Cleaned up test certificate with ID: %d", certId)
					}
				}
			}
		})
	}
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

// TestDuplicateCertificateNames tests what happens when multiple certificates have the same name
func TestDuplicateCertificateNames(t *testing.T) {
	apiToken := os.Getenv("HETZNER_TEST_TOKEN")
	if apiToken == "" {
		t.Skip("Skipping integration test: HETZNER_TEST_TOKEN not set")
	}

	client := hcloud.NewClient(hcloud.WithToken(apiToken))
	ctx := context.Background()

	// Generate two different certificates
	testCert1, testKey1, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("Failed to generate first certificate: %v", err)
	}

	testCert2, testKey2, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("Failed to generate second certificate: %v", err)
	}

	// Create two certificates with the same name
	sameName := fmt.Sprintf("duplicate-test-%d", time.Now().Unix())
	
	// Create first certificate
	cert1Opts := hcloud.CertificateCreateOpts{
		Name:        sameName,
		Type:        hcloud.CertificateTypeUploaded,
		Certificate: string(testCert1),
		PrivateKey:  string(testKey1),
	}
	
	result1, _, err := client.Certificate.Create(ctx, cert1Opts)
	if err != nil {
		t.Fatalf("Failed to create first certificate: %v", err)
	}
	cert1 := result1
	t.Logf("Created first certificate: %s (ID: %d)", cert1.Name, cert1.ID)

	// Try to create second certificate with the same name
	cert2Opts := hcloud.CertificateCreateOpts{
		Name:        sameName,
		Type:        hcloud.CertificateTypeUploaded,
		Certificate: string(testCert2),
		PrivateKey:  string(testKey2),
	}
	
	result2, _, err := client.Certificate.Create(ctx, cert2Opts)
	if err != nil {
		// Check if it's a uniqueness error
		if hcloud.IsError(err, hcloud.ErrorCodeUniquenessError) {
			t.Logf("Cannot create second certificate with same name: uniqueness error")
		} else {
			t.Logf("Failed to create second certificate with error: %v", err)
		}
		
		// Clean up first certificate
		_, _ = client.Certificate.Delete(ctx, cert1)
		return
	}
	
	// If we get here, two certificates with same name were created
	cert2 := result2
	t.Logf("Created second certificate with same name: %s (ID: %d)", cert2.Name, cert2.ID)

	// Test GetByName behavior
	getCert, _, err := client.Certificate.GetByName(ctx, sameName)
	if err != nil {
		t.Logf("GetByName failed with error: %v", err)
	} else if getCert != nil {
		t.Logf("GetByName returned certificate ID: %d", getCert.ID)
	}

	// Clean up
	if cert1 != nil {
		_, _ = client.Certificate.Delete(ctx, cert1)
		t.Logf("Cleaned up certificate ID: %d", cert1.ID)
	}
	if cert2 != nil {
		_, _ = client.Certificate.Delete(ctx, cert2)
		t.Logf("Cleaned up certificate ID: %d", cert2.ID)
	}
}

// TestIntegrationCertificateInUse tests certificate update when the old certificate is in use by a Load Balancer
// It verifies that the store creates a new certificate with a modified name when it can't delete the old one
func TestIntegrationCertificateInUse(t *testing.T) {
	apiToken := os.Getenv("HETZNER_TEST_TOKEN")
	if apiToken == "" {
		t.Skip("Skipping integration test: HETZNER_TEST_TOKEN not set")
	}

	// Generate initial certificate
	testCert1, testKey1, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("Failed to generate first test certificate: %v", err)
	}

	// Generate updated certificate
	testCert2, testKey2, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("Failed to generate second test certificate: %v", err)
	}

	client := hcloud.NewClient(hcloud.WithToken(apiToken))
	ctx := context.Background()

	// Step 1: Create initial certificate
	certName := fmt.Sprintf("cert-sync-lb-test-%d", time.Now().Unix())
	s := &HetznerCloudStore{
		ApiToken:   apiToken,
		CertName:   certName,
		SecretName: "test-secret",
	}

	c1 := &tlssecret.Certificate{
		SecretName:  "test-cert",
		Namespace:   "test",
		Certificate: testCert1,
		Key:         testKey1,
	}

	// Sync initial certificate
	updates1, err := s.Sync(c1)
	if err != nil {
		t.Fatalf("Failed to sync initial certificate: %v", err)
	}

	initialCertId, err := strconv.ParseInt(updates1["cert-id"], 10, 64)
	if err != nil {
		t.Fatalf("Failed to parse initial cert ID: %v", err)
	}
	t.Logf("Created initial certificate with ID: %d", initialCertId)

	// Step 2: Create a Load Balancer and attach the certificate
	lbName := fmt.Sprintf("lb-test-%d", time.Now().Unix())
	
	// Get a network (using the first available network, or create one)
	networks, err := client.Network.All(ctx)
	if err != nil {
		t.Fatalf("Failed to list networks: %v", err)
	}
	
	var network *hcloud.Network
	if len(networks) > 0 {
		network = networks[0]
		t.Logf("Using existing network: %s", network.Name)
	} else {
		// Create a network for testing
		networkOpts := hcloud.NetworkCreateOpts{
			Name:    fmt.Sprintf("test-network-%d", time.Now().Unix()),
			IPRange: &net.IPNet{
				IP:   net.IPv4(10, 0, 0, 0),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
		}
		networkResult, _, err := client.Network.Create(ctx, networkOpts)
		if err != nil {
			t.Fatalf("Failed to create test network: %v", err)
		}
		network = networkResult
		t.Logf("Created test network: %s", network.Name)
		defer func() {
			_, err := client.Network.Delete(ctx, network)
			if err != nil {
				t.Logf("Warning: Failed to delete test network: %v", err)
			}
		}()
	}

	// Create subnet for the network if it doesn't have one
	if len(network.Subnets) == 0 {
		subnetOpts := hcloud.NetworkAddSubnetOpts{
			Subnet: hcloud.NetworkSubnet{
				Type:        hcloud.NetworkSubnetTypeCloud,
				NetworkZone: hcloud.NetworkZoneEUCentral,
				IPRange: &net.IPNet{
					IP:   net.IPv4(10, 0, 0, 0),
					Mask: net.IPv4Mask(255, 255, 255, 0),
				},
			},
		}
		_, _, err := client.Network.AddSubnet(ctx, network, subnetOpts)
		if err != nil {
			t.Logf("Warning: Failed to add subnet to network: %v", err)
		}
	}

	// Get location for Load Balancer
	locations, err := client.Location.All(ctx)
	if err != nil {
		t.Fatalf("Failed to list locations: %v", err)
	}
	if len(locations) == 0 {
		t.Fatal("No locations available")
	}
	location := locations[0]

	// Helper function to get pointer to bool
	boolPtr := func(b bool) *bool { return &b }
	intPtr := func(i int) *int { return &i }

	// Create Load Balancer
	lbOpts := hcloud.LoadBalancerCreateOpts{
		Name:             lbName,
		LoadBalancerType: &hcloud.LoadBalancerType{Name: "lb11"},
		Location:         location,
		PublicInterface:  boolPtr(true),
		Labels: map[string]string{
			"test": "cert-manager-sync",
		},
		Services: []hcloud.LoadBalancerCreateOptsService{
			{
				Protocol:        hcloud.LoadBalancerServiceProtocolHTTPS,
				ListenPort:      intPtr(443),
				DestinationPort: intPtr(80),
				HTTP: &hcloud.LoadBalancerCreateOptsServiceHTTP{
					Certificates: []*hcloud.Certificate{{ID: initialCertId}},
				},
			},
		},
		Targets: []hcloud.LoadBalancerCreateOptsTarget{
			{
				Type: hcloud.LoadBalancerTargetTypeLabelSelector,
				LabelSelector: hcloud.LoadBalancerCreateOptsTargetLabelSelector{
					Selector: "test=cert-manager-sync-nonexistent",
				},
			},
		},
	}

	lbResult, _, err := client.LoadBalancer.Create(ctx, lbOpts)
	if err != nil {
		t.Fatalf("Failed to create Load Balancer: %v", err)
	}
	lb := lbResult.LoadBalancer
	t.Logf("Created Load Balancer: %s (ID: %d) with certificate %d", lb.Name, lb.ID, initialCertId)

	// Clean up Load Balancer at the end
	defer func() {
		t.Log("Cleaning up Load Balancer...")
		_, err := client.LoadBalancer.Delete(ctx, lb)
		if err != nil {
			t.Logf("Warning: Failed to delete test Load Balancer: %v", err)
		} else {
			t.Logf("Deleted test Load Balancer: %s", lb.Name)
		}
	}()

	// Step 3: Update the certificate (should handle the in-use certificate gracefully)
	s.CertId = initialCertId // Set the existing cert ID to simulate an update
	
	c2 := &tlssecret.Certificate{
		SecretName:  "test-cert",
		Namespace:   "test",
		Certificate: testCert2,
		Key:         testKey2,
	}

	t.Log("Attempting to update certificate while it's attached to Load Balancer...")
	updates2, err := s.Sync(c2)
	if err != nil {
		t.Fatalf("Failed to sync updated certificate: %v", err)
	}

	updatedCertId, err := strconv.ParseInt(updates2["cert-id"], 10, 64)
	if err != nil {
		t.Fatalf("Failed to parse updated cert ID: %v", err)
	}
	
	// The implementation should have created a new certificate with a modified name
	if updatedCertId == initialCertId {
		t.Error("Expected a new certificate ID after update, but got the same ID")
	}

	t.Logf("Successfully created new certificate with ID: %d (old ID was %d)", updatedCertId, initialCertId)

	// Verify the new certificate exists and has the expected modified name
	newCert, _, err := client.Certificate.GetByID(ctx, updatedCertId)
	if err != nil || newCert == nil {
		t.Errorf("Failed to retrieve new certificate with ID %d: %v", updatedCertId, err)
	} else {
		expectedName := fmt.Sprintf("%s-%d", certName, initialCertId)
		if newCert.Name != expectedName {
			t.Errorf("Expected certificate name %s, got %s", expectedName, newCert.Name)
		}
		t.Logf("Verified new certificate exists with correct name: %s (ID: %d)", newCert.Name, newCert.ID)
	}

	// Clean up certificates
	defer func() {
		// Clean up the new certificate
		if updatedCertId != initialCertId {
			cert, _, err := client.Certificate.GetByID(ctx, updatedCertId)
			if err == nil && cert != nil {
				_, err = client.Certificate.Delete(ctx, cert)
				if err != nil {
					t.Logf("Warning: Failed to delete new certificate %d: %v", updatedCertId, err)
				} else {
					t.Logf("Cleaned up new certificate with ID: %d", updatedCertId)
				}
			}
		}
		
		// Try to clean up the old certificate (may fail if still in use)
		cert, _, err := client.Certificate.GetByID(ctx, initialCertId)
		if err == nil && cert != nil {
			_, err = client.Certificate.Delete(ctx, cert)
			if err != nil {
				t.Logf("Note: Could not delete initial certificate %d (expected if still in use): %v", initialCertId, err)
			} else {
				t.Logf("Cleaned up initial certificate with ID: %d", initialCertId)
			}
		}
	}()
}

// TestIntegrationCertificateUpdate tests certificate update when the old certificate is NOT in use
// It verifies that the store successfully deletes the old certificate and creates a new one with the same name
func TestIntegrationCertificateUpdate(t *testing.T) {
	apiToken := os.Getenv("HETZNER_TEST_TOKEN")
	if apiToken == "" {
		t.Skip("Skipping integration test: HETZNER_TEST_TOKEN not set")
	}

	// Generate two different certificates
	testCert1, testKey1, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("Failed to generate first certificate: %v", err)
	}

	testCert2, testKey2, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("Failed to generate second certificate: %v", err)
	}

	client := hcloud.NewClient(hcloud.WithToken(apiToken))
	ctx := context.Background()

	// Create initial certificate
	certName := fmt.Sprintf("cert-update-test-%d", time.Now().Unix())
	s := &HetznerCloudStore{
		ApiToken:   apiToken,
		CertName:   certName,
		SecretName: "test-secret",
	}

	c1 := &tlssecret.Certificate{
		SecretName:  "test-cert",
		Namespace:   "test",
		Certificate: testCert1,
		Key:         testKey1,
	}

	// Sync initial certificate
	updates1, err := s.Sync(c1)
	if err != nil {
		t.Fatalf("Failed to sync initial certificate: %v", err)
	}

	initialCertId, err := strconv.ParseInt(updates1["cert-id"], 10, 64)
	if err != nil {
		t.Fatalf("Failed to parse initial cert ID: %v", err)
	}
	t.Logf("Created initial certificate with ID: %d", initialCertId)

	// Update the certificate (should delete old and create new with same name)
	s.CertId = initialCertId
	
	c2 := &tlssecret.Certificate{
		SecretName:  "test-cert",
		Namespace:   "test",
		Certificate: testCert2,
		Key:         testKey2,
	}

	t.Log("Attempting to update certificate (not in use)...")
	updates2, err := s.Sync(c2)
	if err != nil {
		t.Fatalf("Failed to sync updated certificate: %v", err)
	}

	updatedCertId, err := strconv.ParseInt(updates2["cert-id"], 10, 64)
	if err != nil {
		t.Fatalf("Failed to parse updated cert ID: %v", err)
	}

	// The implementation should have created a new certificate with the same name
	if updatedCertId == initialCertId {
		t.Error("Expected a new certificate ID after update, but got the same ID")
	}

	t.Logf("Successfully created new certificate with ID: %d (old ID was %d)", updatedCertId, initialCertId)

	// Verify the new certificate exists with the same name
	newCert, _, err := client.Certificate.GetByID(ctx, updatedCertId)
	if err != nil || newCert == nil {
		t.Errorf("Failed to retrieve new certificate with ID %d: %v", updatedCertId, err)
	} else {
		if newCert.Name != certName {
			t.Errorf("Expected certificate name %s, got %s", certName, newCert.Name)
		}
		t.Logf("Verified new certificate exists with same name: %s (ID: %d)", newCert.Name, newCert.ID)
	}

	// Verify old certificate was deleted
	oldCert, _, err := client.Certificate.GetByID(ctx, initialCertId)
	if err == nil && oldCert != nil {
		t.Errorf("Old certificate %d still exists, expected it to be deleted", initialCertId)
		// Clean up if still exists
		_, _ = client.Certificate.Delete(ctx, oldCert)
	} else {
		t.Logf("Confirmed old certificate %d was deleted", initialCertId)
	}

	// Clean up new certificate
	if newCert != nil {
		_, err = client.Certificate.Delete(ctx, newCert)
		if err != nil {
			t.Logf("Warning: Failed to delete new certificate %d: %v", updatedCertId, err)
		} else {
			t.Logf("Cleaned up new certificate with ID: %d", updatedCertId)
		}
	}
}
