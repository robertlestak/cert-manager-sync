package certmanagersync

import (
	"errors"
	"reflect"
	"testing"

	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNewStore(t *testing.T) {
	tests := []struct {
		name      string
		storeType StoreType
		wantErr   bool
	}{
		{
			name:      "Test ACMStoreType",
			storeType: ACMStoreType,
			wantErr:   false,
		},
		{
			name:      "Test CloudflareStoreType",
			storeType: CloudflareStoreType,
			wantErr:   false,
		},
		{
			name:      "Test DigitalOceanStoreType",
			storeType: DigitalOceanStoreType,
			wantErr:   false,
		},
		{
			name:      "Test FilepathStoreType",
			storeType: FilepathStoreType,
			wantErr:   false,
		},
		{
			name:      "Test GCPStoreType",
			storeType: GCPStoreType,
			wantErr:   false,
		},
		{
			name:      "Test HerokuStoreType",
			storeType: HerokuStoreType,
			wantErr:   false,
		},
		{
			name:      "Test IncapsulaStoreType",
			storeType: IncapsulaStoreType,
			wantErr:   false,
		},
		{
			name:      "Test ThreatxStoreType",
			storeType: ThreatxStoreType,
			wantErr:   false,
		},
		{
			name:      "Test VaultStoreType",
			storeType: VaultStoreType,
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
				assert.True(t, errors.Is(err, ErrInvalidStoreType))
			}
		})
	}
}

func TestEnabledStores(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		want        []StoreType
	}{
		{
			name: "Test with no enabled stores",
			annotations: map[string]string{
				state.OperatorName + "/sync-enabled": "false",
			},
			want: nil,
		},
		{
			name: "Test with ACM and Cloudflare enabled",
			annotations: map[string]string{
				state.OperatorName + "/sync-enabled":       "true",
				state.OperatorName + "/acm-enabled":        "true",
				state.OperatorName + "/cloudflare-enabled": "true",
			},
			want: []StoreType{ACMStoreType, CloudflareStoreType},
		},
		{
			name: "Test with all stores enabled",
			annotations: map[string]string{
				state.OperatorName + "/sync-enabled":         "true",
				state.OperatorName + "/acm-enabled":          "true",
				state.OperatorName + "/cloudflare-enabled":   "true",
				state.OperatorName + "/digitalocean-enabled": "true",
				state.OperatorName + "/filepath-enabled":     "true",
				state.OperatorName + "/gcp-enabled":          "true",
				state.OperatorName + "/heroku-enabled":       "true",
				state.OperatorName + "/incapsula-site-id":    "1234",
				state.OperatorName + "/threatx-hostname":     "example.com",
				state.OperatorName + "/vault-addr":           "https://vault.example.com",
			},
			want: []StoreType{
				ACMStoreType,
				CloudflareStoreType,
				DigitalOceanStoreType,
				FilepathStoreType,
				GCPStoreType,
				HerokuStoreType,
				IncapsulaStoreType,
				ThreatxStoreType,
				VaultStoreType,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: tt.annotations,
				},
			}
			if got := EnabledStores(s); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("EnabledStores() = %v, want %v", got, tt.want)
			}
		})
	}
}
