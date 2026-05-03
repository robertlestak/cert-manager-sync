package state

import (
	"os"
	"strconv"

	corev1 "k8s.io/api/core/v1"
)

const (
	// DeletePolicyRetain leaves the remote certificate in place when the secret is deleted.
	DeletePolicyRetain = "retain"
	// DeletePolicyDelete instructs the operator to delete the remote certificate when the secret is deleted.
	DeletePolicyDelete = "delete"

	deletePolicyAnnotationKey   = "/delete-policy"
	deleteAttemptsAnnotationKey = "/delete-attempts"
	nextDeleteAnnotationKey     = "/next-delete"
)

// FinalizerName returns the namespaced finalizer used to gate secret deletion.
// It is namespaced under OperatorName so users with custom OPERATOR_NAME values get a unique finalizer.
func FinalizerName() string {
	return OperatorName + "/cleanup"
}

// DeletePolicyAnnotation returns the annotation key used for the per-secret delete policy.
func DeletePolicyAnnotation() string {
	return OperatorName + deletePolicyAnnotationKey
}

// DeleteAttemptsAnnotation returns the annotation key used to track delete retry attempts.
func DeleteAttemptsAnnotation() string {
	return OperatorName + deleteAttemptsAnnotationKey
}

// NextDeleteAnnotation returns the annotation key used to schedule the next delete retry.
func NextDeleteAnnotation() string {
	return OperatorName + nextDeleteAnnotationKey
}

// globalDeletePolicy reads DELETE_POLICY env var and returns the normalized cluster-wide default.
// Defaults to retain when unset or invalid to preserve current behavior.
func globalDeletePolicy() string {
	switch os.Getenv("DELETE_POLICY") {
	case DeletePolicyDelete:
		return DeletePolicyDelete
	default:
		return DeletePolicyRetain
	}
}

// EffectiveDeletePolicy returns the resolved delete policy for a secret.
// Per-secret annotation always wins; otherwise the global DELETE_POLICY env var is used.
// Unknown annotation values fall back to the global default rather than silently treating them as delete.
func EffectiveDeletePolicy(s *corev1.Secret) string {
	if s != nil && s.Annotations != nil {
		if v, ok := s.Annotations[DeletePolicyAnnotation()]; ok {
			switch v {
			case DeletePolicyDelete:
				return DeletePolicyDelete
			case DeletePolicyRetain:
				return DeletePolicyRetain
			}
		}
	}
	return globalDeletePolicy()
}

// MaxDeleteAttempts returns the configured maximum number of delete attempts before
// the finalizer is force-removed (when DeleteBlocking is false).
// 0 means retry forever (the finalizer is never force-removed).
// Defaults to 10.
func MaxDeleteAttempts() int {
	v := os.Getenv("MAX_DELETE_ATTEMPTS")
	if v == "" {
		return 10
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 10
	}
	return n
}

// DeleteBlocking reports whether the finalizer must remain in place until remote
// deletion succeeds. Defaults to true (Kubernetes-idiomatic finalizer behavior:
// block secret deletion until the controller succeeds). Set DELETE_BLOCKING=false
// to force-remove the finalizer after MaxDeleteAttempts so a misconfigured store
// cannot permanently wedge a secret.
func DeleteBlocking() bool {
	return os.Getenv("DELETE_BLOCKING") != "false"
}

// HasFinalizer reports whether the secret already carries the operator's finalizer.
func HasFinalizer(s *corev1.Secret) bool {
	if s == nil {
		return false
	}
	target := FinalizerName()
	for _, f := range s.Finalizers {
		if f == target {
			return true
		}
	}
	return false
}

// FinalizersWithout returns the finalizer slice with the operator's finalizer removed.
// Returns the original slice (not a copy) when the finalizer is absent.
func FinalizersWithout(s *corev1.Secret) []string {
	if s == nil {
		return nil
	}
	target := FinalizerName()
	out := make([]string, 0, len(s.Finalizers))
	removed := false
	for _, f := range s.Finalizers {
		if f == target {
			removed = true
			continue
		}
		out = append(out, f)
	}
	if !removed {
		return s.Finalizers
	}
	return out
}

// SecretDeletePending returns true when a secret carries a DeletionTimestamp
// AND has the operator's finalizer (i.e. the operator owes cleanup work).
func SecretDeletePending(s *corev1.Secret) bool {
	if s == nil {
		return false
	}
	if s.DeletionTimestamp == nil {
		return false
	}
	return HasFinalizer(s)
}

