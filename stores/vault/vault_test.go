package vault

import (
	"reflect"
	"testing"
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
