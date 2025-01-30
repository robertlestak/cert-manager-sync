package state

import (
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/stretchr/testify/assert"
)

var mockSecret = &corev1.Secret{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "test-secret",
		Namespace: "default",
		Annotations: map[string]string{
			OperatorName + "/hash": "existingHashValue",
		},
	},
	Data: map[string][]byte{
		"key": []byte("value"),
	},
}

// TestHashSecret checks if HashSecret function returns a consistent hash value
func TestHashSecret(t *testing.T) {
	hash := HashSecret(mockSecret)
	assert.NotEmpty(t, hash, "The hash should not be empty")
}

func TestHashSecretDataAndAnnotationsChange(t *testing.T) {
	// Step 1: Create a base mock secret
	baseMockSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
			Annotations: map[string]string{
				"annotation-key":          "annotation-value",
				OperatorName + "/testing": "annotation-value",
			},
		},
		Data: map[string][]byte{
			"data-key": []byte("data-value"),
		},
	}

	// Generate a hash for the base mock secret
	baseHash := HashSecret(baseMockSecret)
	assert.NotEmpty(t, baseHash, "The base hash should not be empty")

	// Step 2: Modify the secret's data
	modifiedDataSecret := baseMockSecret.DeepCopy()
	modifiedDataSecret.Data["data-key"] = []byte("new-data-value")
	modifiedDataHash := HashSecret(modifiedDataSecret)
	assert.NotEqual(t, baseHash, modifiedDataHash, "Hash should change with data modification")

	// Step 3: Reset the secret to its base state and modify the secret's annotations
	modifiedAnnotationsSecret := baseMockSecret.DeepCopy()
	modifiedAnnotationsSecret.Annotations["annotation-key"] = "new-annotation-value"
	modifiedAnnotationsHash := HashSecret(modifiedAnnotationsSecret)
	assert.Equal(t, baseHash, modifiedAnnotationsHash, "Hash should not change with non-tracked annotation modification")

	// Step 4: Reset the secret to its base state and modify the secret's annotations
	modifiedAnnotationsSecret = baseMockSecret.DeepCopy()
	modifiedAnnotationsSecret.Annotations[OperatorName+"/testing"] = "new-annotation-value"
	modifiedAnnotationsHash = HashSecret(modifiedAnnotationsSecret)
	assert.NotEqual(t, baseHash, modifiedAnnotationsHash, "Hash should change with tracked annotation modification")
}

// TestCmsHash checks if cmsHash correctly extracts the hash from the secret's annotations
func TestCmsHash(t *testing.T) {
	hash := cmsHash(mockSecret)
	assert.Equal(t, "existingHashValue", hash, "The hashes should match")
}

// TestCacheDisable checks different scenarios for cache changes
func TestCacheDisable(t *testing.T) {
	// Scenario 1: Cache is not disabled and hash values are different
	os.Setenv("CACHE_DISABLE", "false")
	changed := CacheChanged(mockSecret)
	assert.True(t, changed, "Cache should be considered changed")

	// Scenario 2: Cache is disabled
	os.Setenv("CACHE_DISABLE", "true")
	changed = CacheChanged(mockSecret)
	assert.True(t, changed, "Cache should always be considered changed when disabled")

	// Cleanup
	os.Unsetenv("CACHE_DISABLE")
}

func TestSecretWatched(t *testing.T) {
	tests := []struct {
		name     string
		secret   *corev1.Secret
		envVars  map[string]string
		expected bool
	}{
		// SECRETS_NAMESPACE is deprecated and has been replaced by ENABLED_NAMESPACES.
		// SECRETS_NAMESPACE will be removed in a future release
		{
			name: "Test with sync-enabled annotation and tls.crt and tls.key data in enabled namespace",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test-secret",
					Namespace:   "test-namespace",
					Annotations: map[string]string{OperatorName + "/sync-enabled": "true"},
				},
				Data: map[string][]byte{
					"tls.crt": []byte("test-crt"),
					"tls.key": []byte("test-key"),
				},
			},
			envVars: map[string]string{
				"SECRETS_NAMESPACE": "test-namespace",
			},
			expected: true,
		},
		{
			name: "Test with sync-enabled annotation and tls.crt and tls.key data in disabled namespace",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test-secret",
					Namespace:   "test-namespace",
					Annotations: map[string]string{OperatorName + "/sync-enabled": "true"},
				},
				Data: map[string][]byte{
					"tls.crt": []byte("test-crt"),
					"tls.key": []byte("test-key"),
				},
			},
			envVars: map[string]string{
				"DISABLED_NAMESPACES": "test-namespace",
			},
			expected: false,
		},
		{
			name: "Test with sync-enabled annotation and tls.crt and tls.key data in enabled namespace",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test-secret",
					Namespace:   "test-namespace",
					Annotations: map[string]string{OperatorName + "/sync-enabled": "true"},
				},
				Data: map[string][]byte{
					"tls.crt": []byte("test-crt"),
					"tls.key": []byte("test-key"),
				},
			},
			envVars: map[string]string{
				"ENABLED_NAMESPACES": "test-namespace,foobar",
			},
			expected: true,
		},
		{
			name: "Test with sync-enabled annotation and tls.crt and tls.key data in default enabled namespace",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test-secret",
					Namespace:   "test-namespace",
					Annotations: map[string]string{OperatorName + "/sync-enabled": "true"},
				},
				Data: map[string][]byte{
					"tls.crt": []byte("test-crt"),
					"tls.key": []byte("test-key"),
				},
			},
			envVars:  nil,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			for key, value := range tt.envVars {
				os.Setenv(key, value)
			}

			if got := SecretWatched(tt.secret); got != tt.expected {
				t.Errorf("SecretWatched() = %v, want %v", got, tt.expected)
			}

			// Unset environment variables
			for key := range tt.envVars {
				os.Unsetenv(key)
			}
		})
	}
}

func TestNamespaceDisabledEnvVar(t *testing.T) {
	os.Setenv("DISABLED_NAMESPACES", "test1,test2")

	tests := []struct {
		name     string
		ns       string
		expected bool
	}{
		{
			name:     "Test with disabled namespace",
			ns:       "test1",
			expected: true,
		},
		{
			name:     "Test with enabled namespace",
			ns:       "test3",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := namespaceDisabled(tt.ns); got != tt.expected {
				t.Errorf("namespaceDisabled() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNamespaceDisabledDefault(t *testing.T) {
	os.Setenv("DISABLED_NAMESPACES", "")
	os.Setenv("SECRETS_NAMESPACE", "")
	os.Setenv("ENABLED_NAMESPACES", "")
	tests := []struct {
		name     string
		ns       string
		expected bool
	}{
		{
			name:     "Test with disabled namespace",
			ns:       "test1",
			expected: false,
		},
		{
			name:     "Test with enabled namespace",
			ns:       "test3",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := namespaceDisabled(tt.ns); got != tt.expected {
				t.Errorf("namespaceDisabled() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNamespaceEnabledEnabledNamespacesList(t *testing.T) {
	os.Setenv("ENABLED_NAMESPACES", "test2,test3")

	tests := []struct {
		name     string
		ns       string
		expected bool
	}{
		{
			name:     "Test with enabled namespace",
			ns:       "test2",
			expected: true,
		},
		{
			name:     "Test with enabled namespace",
			ns:       "test3",
			expected: true,
		},
		{
			name:     "Test with disabled namespace",
			ns:       "test4",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := namespaceEnabled(tt.ns); got != tt.expected {
				t.Errorf("namespaceEnabled() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNamespaceEnabledNamespacesDefault(t *testing.T) {
	os.Setenv("ENABLED_NAMESPACES", "")
	os.Setenv("SECRETS_NAMESPACE", "")
	os.Setenv("DISABLED_NAMESPACES", "")
	tests := []struct {
		name     string
		ns       string
		expected bool
	}{
		{
			name:     "Test with enabled namespace",
			ns:       "test2",
			expected: true,
		},
		{
			name:     "Test with enabled namespace",
			ns:       "test3",
			expected: true,
		},
		{
			name:     "Test with disabled namespace",
			ns:       "test4",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := namespaceEnabled(tt.ns); got != tt.expected {
				t.Errorf("namespaceEnabled() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNamespaceEnabledEnabledSingleSecretsNamespace(t *testing.T) {
	os.Setenv("SECRETS_NAMESPACE", "test1")

	tests := []struct {
		name     string
		ns       string
		expected bool
	}{
		{
			name:     "Test with secrets namespace",
			ns:       "test1",
			expected: true,
		},
		{
			name:     "Test with enabled namespace",
			ns:       "test2",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := namespaceEnabled(tt.ns); got != tt.expected {
				t.Errorf("namespaceEnabled() = %v, want %v", got, tt.expected)
			}
		})
	}
}
