package tlssecret

import (
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/robertlestak/cert-manager-sync/pkg/state"
)

func mapsEqual(m1, m2 map[string]string) bool {
	if len(m1) != len(m2) {
		return false
	}
	for k, v1 := range m1 {
		if v2, ok := m2[k]; !ok || v1 != v2 {
			return false
		}
	}
	return true
}

func secretStoresMetaEqual(m1, m2 map[string][]map[string]string) bool {
	if len(m1) != len(m2) {
		return false
	}
	for k, v1 := range m1 {
		v2, ok := m2[k]
		if !ok {
			return false
		}
		if len(v1) != len(v2) {
			return false
		}
		for i := range v1 {
			if !mapsEqual(v1[i], v2[i]) {
				return false
			}
		}
	}
	return true
}

func TestGetSecretStoresMeta(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		want        map[string][]map[string]string
	}{
		{
			name:        "Test with no annotations",
			annotations: map[string]string{},
			want:        map[string][]map[string]string{},
		},
		{
			name: "Test with one store annotation",
			annotations: map[string]string{
				state.OperatorName + "/acm-key1": "value1",
			},
			want: map[string][]map[string]string{
				"acm": {
					{"key1": "value1"},
				},
			},
		},
		{
			name: "Test with multiple store annotations",
			annotations: map[string]string{
				state.OperatorName + "/acm-key1": "value1",
				state.OperatorName + "/acm-key2": "value2",
				state.OperatorName + "/gcp-key1": "value3",
			},
			want: map[string][]map[string]string{
				"acm": {
					{"key1": "value1"},
					{"key2": "value2"},
				},
				"gcp": {
					{"key1": "value3"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: tt.annotations,
				},
			}
			if got := GetSecretStoresMeta(secret); !secretStoresMetaEqual(got, tt.want) {
				t.Errorf("GetSecretStoresMeta() = %v, want %v", got, tt.want)
			}
		})
	}
}

func compareGenericSecretSyncConfigs(got, want []*GenericSecretSyncConfig) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] == nil || want[i] == nil {
			if got[i] != want[i] {
				return false
			}
			continue
		}
		if got[i].Store != want[i].Store ||
			got[i].Index != want[i].Index ||
			!mapsEqual(got[i].Config, want[i].Config) {
			return false
		}
	}
	return true
}

func TestSecretMetaToGenericSecretSyncConfig(t *testing.T) {
	tests := []struct {
		name string
		meta map[string][]map[string]string
		want []*GenericSecretSyncConfig
	}{
		{
			name: "Test with no meta",
			meta: map[string][]map[string]string{},
			want: []*GenericSecretSyncConfig{},
		},
		{
			name: "Test with one store and one key",
			meta: map[string][]map[string]string{
				"acm": {
					{"arn-role": "value1"},
				},
			},
			want: []*GenericSecretSyncConfig{
				{
					Store:  "acm",
					Index:  -1,
					Config: map[string]string{"arn-role": "value1"},
				},
			},
		},
		{
			name: "Test with one store and multiple keys with index",
			meta: map[string][]map[string]string{
				"acm": {
					{"arn-role.0": "value1"},
					{"arn-role.1": "value2"},
				},
			},
			want: []*GenericSecretSyncConfig{
				{
					Store:  "acm",
					Index:  0,
					Config: map[string]string{"arn-role": "value1"},
				},
				{
					Store:  "acm",
					Index:  1,
					Config: map[string]string{"arn-role": "value2"},
				},
			},
		},
		{
			name: "Test with multiple stores and keys",
			meta: map[string][]map[string]string{
				"acm": {
					{"arn-role": "value1"},
				},
				"gcp": {
					{"project-id": "value2"},
				},
			},
			want: []*GenericSecretSyncConfig{
				{
					Store:  "acm",
					Index:  -1,
					Config: map[string]string{"arn-role": "value1"},
				},
				{
					Store:  "gcp",
					Index:  -1,
					Config: map[string]string{"project-id": "value2"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := SecretMetaToGenericSecretSyncConfig(tt.meta)
			if err != nil {
				t.Errorf("SecretMetaToGenericSecretSyncConfig() error = %v", err)
			}
			if !compareGenericSecretSyncConfigs(m, tt.want) {
				t.Errorf("SecretMetaToGenericSecretSyncConfig() = %v, want %v", m, tt.want)
			}
		})
	}
}

func TestSyncsForStore(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		Store       string
		want        []*GenericSecretSyncConfig
		wantErr     bool
	}{
		{
			name:        "Test with no annotations",
			annotations: map[string]string{},
			Store:       "acm",
			want:        []*GenericSecretSyncConfig{},
			wantErr:     false,
		},
		{
			name: "Test with one store annotation",
			annotations: map[string]string{
				state.OperatorName + "/acm-arn-role": "value1",
			},
			Store: "acm",
			want: []*GenericSecretSyncConfig{
				{
					Store:  "acm",
					Index:  -1,
					Config: map[string]string{"arn-role": "value1"},
				},
			},
			wantErr: false,
		},
		{
			name: "Test with multiple store annotations",
			annotations: map[string]string{
				state.OperatorName + "/acm-arn-role":   "value1",
				state.OperatorName + "/gcp-project-id": "value2",
			},
			Store: "acm",
			want: []*GenericSecretSyncConfig{
				{
					Store:  "acm",
					Index:  -1,
					Config: map[string]string{"arn-role": "value1"},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: tt.annotations,
				},
			}
			got, err := SyncsForStore(secret, tt.Store)
			if (err != nil) != tt.wantErr {
				t.Errorf("SyncsForStore() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !compareGenericSecretSyncConfigs(got, tt.want) {
				t.Errorf("SyncsForStore() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAnnotationUpdates(t *testing.T) {
	tests := []struct {
		name string
		c    *Certificate
		want map[string]string
	}{
		{
			name: "Test with no updates",
			c: &Certificate{
				Syncs: []*GenericSecretSyncConfig{},
			},
			want: map[string]string{},
		},
		{
			name: "Test with one update and no index",
			c: &Certificate{
				Syncs: []*GenericSecretSyncConfig{
					{
						Store: "acm",
						Index: -1,
						Updates: map[string]string{
							"key1": "value1",
						},
					},
				},
			},
			want: map[string]string{
				state.OperatorName + "/acm-key1": "value1",
			},
		},
		{
			name: "Test with multiple updates and indices",
			c: &Certificate{
				Syncs: []*GenericSecretSyncConfig{
					{
						Store: "acm",
						Index: -1,
						Updates: map[string]string{
							"key1": "value1",
						},
					},
					{
						Store: "gcp",
						Index: 1,
						Updates: map[string]string{
							"key2": "value2",
						},
					},
				},
			},
			want: map[string]string{
				state.OperatorName + "/acm-key1":   "value1",
				state.OperatorName + "/gcp-key2.1": "value2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AnnotationUpdates(tt.c)
			if !mapsEqual(got, tt.want) {
				t.Errorf("AnnotationUpdates() = %v, want %v", got, tt.want)
			}
		})
	}
}
