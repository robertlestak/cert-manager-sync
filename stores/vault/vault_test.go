package vault

import (
	"reflect"
	"testing"

	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
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

func TestParseCertificate(t *testing.T) {
	tests := []struct {
		name        string
		certificate *tlssecret.Certificate
		want        *VaultStore
	}{
		{
			name: "Test with valid annotations",
			certificate: &tlssecret.Certificate{
				Annotations: map[string]string{
					state.OperatorName + "/vault-path":        "test-path",
					state.OperatorName + "/vault-addr":        "test-addr",
					state.OperatorName + "/vault-namespace":   "test-namespace",
					state.OperatorName + "/vault-role":        "test-role",
					state.OperatorName + "/vault-auth-method": "test-auth-method",
				},
			},
			want: &VaultStore{
				Path:       "test-path",
				Addr:       "test-addr",
				Namespace:  "test-namespace",
				Role:       "test-role",
				AuthMethod: "test-auth-method",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := &VaultStore{}
			if err := vs.ParseCertificate(tt.certificate); err != nil {
				t.Errorf("ParseCertificate() error = %v", err)
				return
			}
			if vs.Path != tt.want.Path || vs.Addr != tt.want.Addr || vs.Namespace != tt.want.Namespace || vs.Role != tt.want.Role || vs.AuthMethod != tt.want.AuthMethod {
				t.Errorf("ParseCertificate() = %v, want %v", vs, tt.want)
			}
		})
	}
}
