package state

import (
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCacheChangedAndAddToCache(t *testing.T) {
	tests := []struct {
		name           string
		secret         *corev1.Secret
		modifiedSecret *corev1.Secret
		expected       bool
	}{
		{
			name: "Test with new secret",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-namespace",
				},
				Data: map[string][]byte{
					"tls.crt": []byte("test-crt"),
					"tls.key": []byte("test-key"),
				},
			},
			modifiedSecret: nil,
			expected:       false,
		},
		{
			name: "Test with existing secret with no changes",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-namespace",
				},
				Data: map[string][]byte{
					"tls.crt": []byte("test-crt"),
					"tls.key": []byte("test-key"),
				},
			},
			modifiedSecret: nil,
			expected:       false,
		},
		{
			name: "Test with existing secret with data changes",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-namespace",
				},
				Data: map[string][]byte{
					"tls.crt": []byte("test-crt"),
					"tls.key": []byte("test-key"),
				},
			},
			modifiedSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-namespace",
				},
				Data: map[string][]byte{
					"tls.crt": []byte("test-crt-changed"),
					"tls.key": []byte("test-key"),
				},
			},
			expected: true,
		},
		{
			name: "Test with existing secret without metadata changes",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-namespace",
					Annotations: map[string]string{
						"test-annotation": "test-annotation-value",
					},
				},
				Data: map[string][]byte{
					"tls.crt": []byte("test-crt"),
					"tls.key": []byte("test-key"),
				},
			},
			modifiedSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-namespace",
					Annotations: map[string]string{
						"test-annotation": "test-annotation-value",
					},
				},
				Data: map[string][]byte{
					"tls.crt": []byte("test-crt"),
					"tls.key": []byte("test-key"),
				},
			},
			expected: false,
		},
		{
			name: "Test with existing secret wit metadata changes",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-namespace",
					Annotations: map[string]string{
						"test-annotation": "test-annotation-value",
					},
				},
				Data: map[string][]byte{
					"tls.crt": []byte("test-crt"),
					"tls.key": []byte("test-key"),
				},
			},
			modifiedSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-namespace",
					Annotations: map[string]string{
						"test-annotation": "test-annotation-value-changed",
					},
				},
				Data: map[string][]byte{
					"tls.crt": []byte("test-crt"),
					"tls.key": []byte("test-key"),
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			AddToCache(tt.secret)
			if tt.modifiedSecret == nil {
				tt.modifiedSecret = tt.secret
			}
			if got := CacheChanged(tt.modifiedSecret); got != tt.expected {
				t.Errorf("CacheChanged() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestStringMapChanged(t *testing.T) {
	tests := []struct {
		name     string
		a        map[string]string
		b        map[string]string
		expected bool
	}{
		{
			name: "Test with two identical maps",
			a: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			b: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			expected: false,
		},
		{
			name: "Test with two maps of different lengths",
			a: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			b: map[string]string{
				"key1": "value1",
			},
			expected: true,
		},
		{
			name: "Test with two maps with different values for the same key",
			a: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			b: map[string]string{
				"key1": "value1",
				"key2": "value3",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stringMapChanged(tt.a, tt.b); got != tt.expected {
				t.Errorf("stringMapChanged() = %v, want %v", got, tt.expected)
			}
		})
	}
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
