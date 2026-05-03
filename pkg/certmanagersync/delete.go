package certmanagersync

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// DeletableRemoteStore is implemented by stores that support deleting a previously-synced
// remote certificate. Stores that do not implement this interface are skipped during
// delete reconciliation; their remote state is left untouched.
//
// Implementations must:
//   - Treat "not found" responses from the remote as success (idempotent delete).
//   - Operate on the identifiers populated by FromConfig (e.g. CertificateArn,
//     CertificateName, CertId, Path) — they should not require a Certificate.
type DeletableRemoteStore interface {
	Delete(ctx context.Context) error
}

// patcher is the subset of the corev1 Secret API used by finalizer/annotation patches.
// It is satisfied by typedcorev1.SecretInterface and is parameterized so the helpers
// can be unit-tested against a fake clientset.
type patcher interface {
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (*corev1.Secret, error)
}

// secretsClient returns the corev1 SecretInterface used to patch the operator's
// finalizer and delete-tracking annotations. Defined as a var so tests may swap it.
var secretsClient = func(namespace string) patcher {
	return state.KubeClient.CoreV1().Secrets(namespace)
}

// EnsureFinalizer adds the operator finalizer to the secret if it is not already present
// and the secret is not pending deletion. Returns true if a patch was issued.
//
// Uses strategic merge patch so that finalizers added by other controllers
// between our Read and Patch are not clobbered (JSON merge patch would
// replace the entire array wholesale).
func EnsureFinalizer(ctx context.Context, s *corev1.Secret) (bool, error) {
	if s == nil {
		return false, nil
	}
	if s.DeletionTimestamp != nil {
		return false, nil
	}
	if state.HasFinalizer(s) {
		return false, nil
	}
	// Strategic merge patch on Secret.metadata.finalizers merges by string
	// identity (deduplicated), preserving any finalizers added by other
	// controllers concurrently.
	patch := map[string]interface{}{
		"metadata": map[string]interface{}{
			"finalizers": []string{state.FinalizerName()},
		},
	}
	pd, err := json.Marshal(patch)
	if err != nil {
		return false, fmt.Errorf("marshal finalizer patch: %w", err)
	}
	if _, err := secretsClient(s.Namespace).Patch(ctx, s.Name, types.StrategicMergePatchType, pd, metav1.PatchOptions{}); err != nil {
		return false, fmt.Errorf("add finalizer to %s/%s: %w", s.Namespace, s.Name, err)
	}
	// Do NOT mutate s.Finalizers in place — s comes from the shared informer
	// cache. The next event for this secret will deliver fresh state from the
	// API server.
	return true, nil
}

// RemoveFinalizer removes the operator finalizer from the secret if present.
// Returns true if a patch was issued.
//
// Uses the strategic merge patch `$deleteFromPrimitiveList` directive to
// remove a single value from the finalizers array without clobbering
// finalizers added concurrently by other controllers.
func RemoveFinalizer(ctx context.Context, s *corev1.Secret) (bool, error) {
	if s == nil || !state.HasFinalizer(s) {
		return false, nil
	}
	patch := map[string]interface{}{
		"metadata": map[string]interface{}{
			"$deleteFromPrimitiveList/finalizers": []string{state.FinalizerName()},
		},
	}
	pd, err := json.Marshal(patch)
	if err != nil {
		return false, fmt.Errorf("marshal finalizer patch: %w", err)
	}
	if _, err := secretsClient(s.Namespace).Patch(ctx, s.Name, types.StrategicMergePatchType, pd, metav1.PatchOptions{}); err != nil {
		return false, fmt.Errorf("remove finalizer from %s/%s: %w", s.Namespace, s.Name, err)
	}
	// Do NOT mutate s.Finalizers in place — see EnsureFinalizer.
	return true, nil
}

// patchDeleteRetry records a failed delete attempt and schedules the next retry.
// Patches both the attempt counter and the next-delete timestamp annotations.
func patchDeleteRetry(ctx context.Context, s *corev1.Secret, attempts int, nextRetry time.Time) error {
	patch := map[string]interface{}{
		"metadata": map[string]interface{}{
			"annotations": map[string]string{
				state.DeleteAttemptsAnnotation(): strconv.Itoa(attempts),
				state.NextDeleteAnnotation():     nextRetry.Format(time.RFC3339),
			},
		},
	}
	pd, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("marshal delete retry patch: %w", err)
	}
	if _, err := secretsClient(s.Namespace).Patch(ctx, s.Name, types.MergePatchType, pd, metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("patch delete retry annotations on %s/%s: %w", s.Namespace, s.Name, err)
	}
	return nil
}

// deleteAttempts returns the current count of failed delete attempts recorded on the secret.
func deleteAttempts(s *corev1.Secret) int {
	if s == nil || s.Annotations == nil {
		return 0
	}
	v := s.Annotations[state.DeleteAttemptsAnnotation()]
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// nextDeleteTime returns the scheduled next-delete time, or zero time if unset.
func nextDeleteTime(s *corev1.Secret) time.Time {
	if s == nil || s.Annotations == nil {
		return time.Time{}
	}
	v := s.Annotations[state.NextDeleteAnnotation()]
	if v == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}
	}
	return t
}

// readyToRetryDelete reports whether the next-delete backoff has elapsed.
func readyToRetryDelete(s *corev1.Secret) bool {
	t := nextDeleteTime(s)
	if t.IsZero() {
		return true
	}
	return !time.Now().Before(t)
}

// HandleSecretDelete reconciles the deletion of a secret carrying the operator finalizer.
// It walks the per-store sync configs encoded on the secret, calls Delete on stores that
// implement DeletableRemoteStore, and removes the finalizer when all capable stores have
// reported success (or when the configured failure policy says to give up).
//
// The secret passed in is expected to already carry a DeletionTimestamp and the operator
// finalizer; callers should gate via state.SecretDeletePending.
//
// Returns nil when the finalizer has been removed (success or give-up), and a non-nil
// error when the caller should retry later. The caller is not expected to mutate s.
func HandleSecretDelete(s *corev1.Secret) error {
	l := log.WithFields(log.Fields{
		"action":    "HandleSecretDelete",
		"namespace": s.Namespace,
		"name":      s.Name,
	})
	if !state.HasFinalizer(s) {
		// Nothing for us to do; another path already removed our finalizer.
		l.Debug("finalizer not present; nothing to clean up")
		return nil
	}
	if !readyToRetryDelete(s) {
		l.Debug("delete backoff not elapsed; deferring")
		return nil
	}

	ctx := context.Background()

	// If the secret was never opted in to deletion, just drop the finalizer.
	// This handles a user removing the annotation between "ensure finalizer" and the
	// actual deletion event — we should not leave them stuck.
	if state.EffectiveDeletePolicy(s) != state.DeletePolicyDelete {
		l.Debug("delete policy is retain; removing finalizer without remote cleanup")
		if _, err := RemoveFinalizer(ctx, s); err != nil {
			return err
		}
		return nil
	}

	cert := tlssecret.ParseSecret(s)
	if cert == nil {
		// Without parseable annotations we have nothing to act on. Don't keep the
		// secret wedged forever; drop the finalizer and warn.
		l.Warn("unable to parse secret on delete; removing finalizer")
		if state.EventRecorder != nil {
			state.EventRecorder.Event(s, corev1.EventTypeWarning, "DeleteSkipped", "Unable to parse secret on delete; finalizer removed without remote cleanup")
		}
		if _, err := RemoveFinalizer(ctx, s); err != nil {
			return err
		}
		return nil
	}

	var errs []error
	skippedStores := 0
	for _, sync := range cert.Syncs {
		ll := l.WithFields(log.Fields{"store": sync.Store, "index": sync.Index})
		rs, err := newStoreFn(sync.Store)
		if err != nil {
			ll.WithError(err).Errorf("failed to initialize store for delete")
			errs = append(errs, fmt.Errorf("init store %s: %w", sync.Store, err))
			continue
		}
		// During Sync, stores derive the credentials-secret namespace by
		// running `s.SecretNamespace = c.Namespace` AFTER FromConfig. We have
		// no Certificate to pass here (the secret is being deleted, possibly
		// with empty data), so we replicate that defaulting by ensuring the
		// `secret-name` annotation carries an explicit `<namespace>/<name>`
		// prefix before FromConfig runs. Every store's FromConfig parses that
		// prefix into SecretNamespace, so this single shim covers all stores
		// without per-store edits.
		cfg := withSecretNamespaceDefault(*sync, s.Namespace)
		if err := rs.FromConfig(cfg); err != nil {
			ll.WithError(err).Errorf("failed to configure store for delete")
			errs = append(errs, fmt.Errorf("configure store %s: %w", sync.Store, err))
			continue
		}
		deleter, ok := rs.(DeletableRemoteStore)
		if !ok {
			ll.Debug("store does not implement DeletableRemoteStore; skipping remote cleanup")
			if state.EventRecorder != nil {
				state.EventRecorder.Eventf(s, corev1.EventTypeNormal, "DeleteSkipped", "Store %s does not support delete; remote state unchanged", sync.Store)
			}
			skippedStores++
			continue
		}
		if err := deleter.Delete(ctx); err != nil {
			ll.WithError(err).Errorf("remote delete failed")
			errs = append(errs, fmt.Errorf("delete from store %s: %w", sync.Store, err))
			continue
		}
		ll.Info("remote certificate deleted")
		if state.EventRecorder != nil {
			state.EventRecorder.Eventf(s, corev1.EventTypeNormal, "Deleted", "Deleted remote certificate from store %s", sync.Store)
		}
	}

	if len(errs) == 0 {
		if state.EventRecorder != nil {
			state.EventRecorder.Eventf(s, corev1.EventTypeNormal, "DeleteCompleted", "Remote cleanup complete (%d stores synced, %d skipped); removing finalizer", len(cert.Syncs)-skippedStores, skippedStores)
		}
		if _, err := RemoveFinalizer(ctx, s); err != nil {
			return err
		}
		return nil
	}

	// Failure path: increment attempt counter and decide whether to keep retrying.
	attempts := deleteAttempts(s) + 1
	maxAttempts := state.MaxDeleteAttempts()
	blocking := state.DeleteBlocking()

	for _, e := range errs {
		l.WithError(e).Error("delete error detail")
	}

	if maxAttempts > 0 && attempts >= maxAttempts && !blocking {
		// Give up: force-remove the finalizer so the secret can finalize.
		// The remote cert remains and will need manual cleanup; emit a loud warning.
		l.WithField("attempts", attempts).Warn("max delete attempts reached; force-removing finalizer (DELETE_BLOCKING=false)")
		if state.EventRecorder != nil {
			state.EventRecorder.Eventf(s, corev1.EventTypeWarning, "DeleteGaveUp",
				"Failed to delete remote certificate after %d attempts; finalizer force-removed because DELETE_BLOCKING=false. Remote certificate may need manual cleanup. Errors: %v",
				attempts, errs)
		}
		if _, err := RemoveFinalizer(ctx, s); err != nil {
			return err
		}
		return nil
	}

	nextRetry := calculateNextDeleteRetry(attempts)
	if err := patchDeleteRetry(ctx, s, attempts, nextRetry); err != nil {
		// If we can't persist the attempt counter / next-retry, the caller will
		// keep retrying without backoff — bounded only by the informer resync
		// period. Surface this via a Warning event so it's visible in
		// `kubectl describe secret`, since this typically indicates an RBAC
		// problem that needs operator attention.
		l.WithError(err).Error("failed to record delete retry state; subsequent retries will not be rate-limited until this patch succeeds")
		if state.EventRecorder != nil {
			state.EventRecorder.Eventf(s, corev1.EventTypeWarning, "DeleteRetryStateUnpersisted",
				"Could not patch delete-attempts/next-delete annotations (RBAC?): %v", err)
		}
	}
	if state.EventRecorder != nil {
		state.EventRecorder.Eventf(s, corev1.EventTypeWarning, "DeleteFailed",
			"Remote delete failed (attempt %d, retrying at %s): %v", attempts, nextRetry.Format(time.RFC3339), errs)
	}
	return fmt.Errorf("delete reconcile errors for %s/%s (attempt %d): %v", s.Namespace, s.Name, attempts, errs)
}

// withSecretNamespaceDefault returns a deep-enough copy of the sync config with
// `secret-name` rewritten to `<namespace>/<name>` when it lacks a namespace
// prefix. The K8s secret being reconciled is the source of truth for the
// credentials-secret namespace, mirroring the existing Sync behavior of
// `s.SecretNamespace = c.Namespace`.
//
// No-op when `secret-name` is unset (filepath, vault) or already namespaced.
// We never mutate the caller's config to keep cert.Syncs safe to reuse.
func withSecretNamespaceDefault(in tlssecret.GenericSecretSyncConfig, namespace string) tlssecret.GenericSecretSyncConfig {
	out := in
	if in.Config == nil {
		return out
	}
	name := in.Config["secret-name"]
	if name == "" || strings.Contains(name, "/") {
		return out
	}
	if namespace == "" {
		return out
	}
	cfg := make(map[string]string, len(in.Config))
	for k, v := range in.Config {
		cfg[k] = v
	}
	cfg["secret-name"] = namespace + "/" + name
	out.Config = cfg
	return out
}

// calculateNextDeleteRetry returns the timestamp at which the next delete attempt
// should run. Uses the same binary exponential backoff as sync retries, capped at
// 32 hours.
func calculateNextDeleteRetry(attempts int) time.Time {
	var delay time.Duration
	switch {
	case attempts < 1:
		delay = time.Minute
	case attempts >= 31:
		delay = 32 * time.Hour
	default:
		delay = time.Duration(1<<uint(attempts-1)) * time.Minute
	}
	if delay > 32*time.Hour {
		delay = 32 * time.Hour
	}
	return time.Now().Add(delay)
}
