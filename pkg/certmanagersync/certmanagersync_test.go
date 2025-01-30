package certmanagersync

import (
	"errors"
	"testing"
	"time"

	cmtypes "github.com/robertlestak/cert-manager-sync/internal/types"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNewStore(t *testing.T) {
	tests := []struct {
		name      string
		storeType cmtypes.StoreType
		wantErr   bool
	}{
		{
			name:      "Test ACMStoreType",
			storeType: cmtypes.ACMStoreType,
			wantErr:   false,
		},
		{
			name:      "Test CloudflareStoreType",
			storeType: cmtypes.CloudflareStoreType,
			wantErr:   false,
		},
		{
			name:      "Test DigitalOceanStoreType",
			storeType: cmtypes.DigitalOceanStoreType,
			wantErr:   false,
		},
		{
			name:      "Test FilepathStoreType",
			storeType: cmtypes.FilepathStoreType,
			wantErr:   false,
		},
		{
			name:      "Test GCPStoreType",
			storeType: cmtypes.GCPStoreType,
			wantErr:   false,
		},
		{
			name:      "Test HerokuStoreType",
			storeType: cmtypes.HerokuStoreType,
			wantErr:   false,
		},
		{
			name:      "Test IncapsulaStoreType",
			storeType: cmtypes.IncapsulaStoreType,
			wantErr:   false,
		},
		{
			name:      "Test ThreatxStoreType",
			storeType: cmtypes.ThreatxStoreType,
			wantErr:   false,
		},
		{
			name:      "Test VaultStoreType",
			storeType: cmtypes.VaultStoreType,
			wantErr:   false,
		},
		{
			name:      "Test invalid store type",
			storeType: "invalid",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewStore(tt.storeType)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewStore() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.wantErr {
				assert.True(t, errors.Is(err, cmtypes.ErrInvalidStoreType))
			}
		})
	}
}

// helper function to create a secret with annotations
func createSecretWithAnnotations(name string, annotations map[string]string) *v1.Secret {
	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Annotations: annotations,
		},
	}
}

func TestRetryLogic(t *testing.T) {
	tests := []struct {
		name           string
		secret         *v1.Secret
		expectedResult bool
	}{
		{
			name:           "No annotations should allow retry",
			secret:         createSecretWithAnnotations("secret1", nil),
			expectedResult: true,
		},
		{
			name: "Under max retries should allow retry",
			secret: createSecretWithAnnotations("secret2", map[string]string{
				state.OperatorName + "/max-sync-attempts":    "5",
				state.OperatorName + "/failed-sync-attempts": "2",
			}),
			expectedResult: true,
		},
		{
			name: "Reached max retries should not allow retry",
			secret: createSecretWithAnnotations("secret3", map[string]string{
				state.OperatorName + "/max-sync-attempts":    "5",
				state.OperatorName + "/failed-sync-attempts": "5",
			}),
			expectedResult: false,
		},
		{
			name: "Next retry time in the future should not allow retry",
			secret: createSecretWithAnnotations("secret4", map[string]string{
				state.OperatorName + "/next-retry": time.Now().Add(1 * time.Hour).Format(time.RFC3339),
			}),
			expectedResult: false,
		},
		{
			name: "Next retry time in the past should allow retry",
			secret: createSecretWithAnnotations("secret5", map[string]string{
				state.OperatorName + "/next-retry": time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
			}),
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := readyToRetry(tt.secret)
			if result != tt.expectedResult {
				t.Errorf("expected %v, got %v", tt.expectedResult, result)
			}
		})
	}
}

func TestCalculateNextRetryTime(t *testing.T) {
	tests := []struct {
		name          string
		secret        *corev1.Secret
		expectedDelay time.Duration
	}{
		{
			name: "Initial retry",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test-secret",
					Annotations: map[string]string{},
				},
			},
			expectedDelay: 1 * time.Minute,
		},
		{
			name: "Second retry",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-secret",
					Annotations: map[string]string{
						state.OperatorName + "/failed-sync-attempts": "1",
					},
				},
			},
			expectedDelay: 2 * time.Minute,
		},
		{
			name: "Third retry",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-secret",
					Annotations: map[string]string{
						state.OperatorName + "/failed-sync-attempts": "2",
					},
				},
			},
			expectedDelay: 4 * time.Minute,
		},
		{
			name: "Max retry delay",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-secret",
					Annotations: map[string]string{
						state.OperatorName + "/failed-sync-attempts": "999999999",
					},
				},
			},
			expectedDelay: 32 * time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			startTime := time.Now()
			nextRetryTime := calculateNextRetryTime(tt.secret)
			expectedNextRetryTime := startTime.Add(tt.expectedDelay)
			// Allow a small margin for timing differences
			assert.WithinDuration(t, expectedNextRetryTime, nextRetryTime, time.Minute)
		})
	}
}
