package state

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func clearDeleteEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DELETE_POLICY", "")
	t.Setenv("MAX_DELETE_ATTEMPTS", "")
	t.Setenv("DELETE_BLOCKING", "")
}

func TestEffectiveDeletePolicy(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		annot    map[string]string
		want     string
	}{
		{
			name: "default with no env or annotation is retain",
			want: DeletePolicyRetain,
		},
		{
			name:     "global delete env",
			envValue: DeletePolicyDelete,
			want:     DeletePolicyDelete,
		},
		{
			name:     "global retain env",
			envValue: DeletePolicyRetain,
			want:     DeletePolicyRetain,
		},
		{
			name:  "annotation delete overrides empty env",
			annot: map[string]string{DeletePolicyAnnotation(): DeletePolicyDelete},
			want:  DeletePolicyDelete,
		},
		{
			name:     "annotation retain overrides global delete",
			envValue: DeletePolicyDelete,
			annot:    map[string]string{DeletePolicyAnnotation(): DeletePolicyRetain},
			want:     DeletePolicyRetain,
		},
		{
			name:     "annotation delete overrides global retain",
			envValue: DeletePolicyRetain,
			annot:    map[string]string{DeletePolicyAnnotation(): DeletePolicyDelete},
			want:     DeletePolicyDelete,
		},
		{
			name:     "unknown annotation falls back to global",
			envValue: DeletePolicyDelete,
			annot:    map[string]string{DeletePolicyAnnotation(): "garbage"},
			want:     DeletePolicyDelete,
		},
		{
			name:     "unknown env falls back to retain",
			envValue: "garbage",
			want:     DeletePolicyRetain,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearDeleteEnv(t)
			t.Setenv("DELETE_POLICY", tt.envValue)
			s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Annotations: tt.annot}}
			assert.Equal(t, tt.want, EffectiveDeletePolicy(s))
		})
	}
}

func TestEffectiveDeletePolicyNilSecret(t *testing.T) {
	clearDeleteEnv(t)
	t.Setenv("DELETE_POLICY", DeletePolicyDelete)
	assert.Equal(t, DeletePolicyDelete, EffectiveDeletePolicy(nil))
}

func TestMaxDeleteAttempts(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want int
	}{
		{name: "default when unset", env: "", want: 10},
		{name: "valid positive", env: "5", want: 5},
		{name: "zero means forever", env: "0", want: 0},
		{name: "negative is invalid, fall back to default", env: "-3", want: 10},
		{name: "non-numeric falls back to default", env: "abc", want: 10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("MAX_DELETE_ATTEMPTS", tt.env)
			assert.Equal(t, tt.want, MaxDeleteAttempts())
		})
	}
}

func TestDeleteBlocking(t *testing.T) {
	t.Setenv("DELETE_BLOCKING", "")
	assert.True(t, DeleteBlocking(), "default should be true (Kubernetes-idiomatic finalizer behavior)")
	t.Setenv("DELETE_BLOCKING", "true")
	assert.True(t, DeleteBlocking())
	t.Setenv("DELETE_BLOCKING", "false")
	assert.False(t, DeleteBlocking(), "explicit false disables blocking")
	// any value other than the literal "false" keeps blocking on
	t.Setenv("DELETE_BLOCKING", "0")
	assert.True(t, DeleteBlocking())
	t.Setenv("DELETE_BLOCKING", "no")
	assert.True(t, DeleteBlocking())
}

func TestFinalizerName(t *testing.T) {
	assert.Equal(t, OperatorName+"/cleanup", FinalizerName())
}

func TestHasFinalizer(t *testing.T) {
	assert.False(t, HasFinalizer(nil))
	s := &corev1.Secret{}
	assert.False(t, HasFinalizer(s))
	s.Finalizers = []string{"other.example.com/foo"}
	assert.False(t, HasFinalizer(s))
	s.Finalizers = append(s.Finalizers, FinalizerName())
	assert.True(t, HasFinalizer(s))
}

func TestFinalizersWithout(t *testing.T) {
	t.Run("nil secret", func(t *testing.T) {
		assert.Nil(t, FinalizersWithout(nil))
	})
	t.Run("absent finalizer returns original slice", func(t *testing.T) {
		s := &corev1.Secret{}
		s.Finalizers = []string{"other/foo"}
		got := FinalizersWithout(s)
		assert.Equal(t, []string{"other/foo"}, got)
	})
	t.Run("removes only operator finalizer", func(t *testing.T) {
		s := &corev1.Secret{}
		s.Finalizers = []string{"other/foo", FinalizerName(), "other/bar"}
		got := FinalizersWithout(s)
		assert.Equal(t, []string{"other/foo", "other/bar"}, got)
	})
	t.Run("idempotent on already-empty", func(t *testing.T) {
		s := &corev1.Secret{}
		got := FinalizersWithout(s)
		assert.Empty(t, got)
	})
}

func TestSecretDeletePending(t *testing.T) {
	now := metav1.Now()
	tests := []struct {
		name string
		s    *corev1.Secret
		want bool
	}{
		{name: "nil", s: nil, want: false},
		{name: "no deletion timestamp", s: &corev1.Secret{}, want: false},
		{
			name: "deletion timestamp but no finalizer",
			s: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{DeletionTimestamp: &now},
			},
			want: false,
		},
		{
			name: "deletion timestamp with our finalizer",
			s: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					DeletionTimestamp: &now,
					Finalizers:        []string{FinalizerName()},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, SecretDeletePending(tt.s))
		})
	}
}

// Defensive: ensure os.Setenv cleanup works and globalDeletePolicy reads env each call.
func TestGlobalDeletePolicyReadsLive(t *testing.T) {
	clearDeleteEnv(t)
	assert.Equal(t, DeletePolicyRetain, globalDeletePolicy())
	os.Setenv("DELETE_POLICY", DeletePolicyDelete)
	defer os.Unsetenv("DELETE_POLICY")
	assert.Equal(t, DeletePolicyDelete, globalDeletePolicy())
}
