package hetznercloud

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
)

// ccmCertificatesAnnotation is the hcloud-cloud-controller-manager annotation
// listing the certificates (by name or ID) of an HTTPS Load Balancer service.
const ccmCertificatesAnnotation = "load-balancer.hetzner.cloud/http-certificates"

// Overridden in tests to keep them fast.
var (
	unusedPollTimeout  = 90 * time.Second
	unusedPollInterval = 5 * time.Second
)

// parseServiceRefs parses "ns/name,ns/name". Entries without a namespace use
// defaultNamespace.
func parseServiceRefs(s, defaultNamespace string) ([]k8stypes.NamespacedName, error) {
	var refs []k8stypes.NamespacedName
	for _, raw := range strings.Split(s, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		parts := strings.Split(raw, "/")
		switch {
		case len(parts) == 1:
			refs = append(refs, k8stypes.NamespacedName{Namespace: defaultNamespace, Name: parts[0]})
		case len(parts) == 2 && parts[0] != "" && parts[1] != "":
			refs = append(refs, k8stypes.NamespacedName{Namespace: parts[0], Name: parts[1]})
		default:
			return nil, fmt.Errorf("invalid service reference %q, expected namespace/name", raw)
		}
	}
	return refs, nil
}

func parseIDs(s string) []int64 {
	var ids []int64
	for _, raw := range strings.Split(s, ",") {
		if id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64); err == nil && id > 0 {
			ids = append(ids, id)
		}
	}
	return ids
}

func joinIDs(ids []int64) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.FormatInt(id, 10)
	}
	return strings.Join(parts, ",")
}

// replaceCertRefs swaps every entry of a comma-separated certificate list that
// matches one of oldRefs (a name or an ID) for newID. It reports whether
// anything was replaced; other entries (e.g. extra SNI certificates) are kept.
func replaceCertRefs(annotation string, oldRefs []string, newID int64) (string, bool) {
	newRef := strconv.FormatInt(newID, 10)
	entries := strings.Split(annotation, ",")
	replaced := false
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		for _, old := range oldRefs {
			if old != "" && e == old {
				e = newRef
				replaced = true
				break
			}
		}
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	return strings.Join(out, ","), replaced
}

// updateServices points the listed Services' CCM certificate annotation at the
// new certificate. A Service that does not reference the old certificate is
// left untouched, so the operator never attaches certificates on its own.
func (s *HetznerCloudStore) updateServices(ctx context.Context, oldRefs []string, newID int64) error {
	var errs []string
	for _, ref := range s.Services {
		l := log.WithFields(log.Fields{"store": "hetznercloud", "service": ref.String(), "newCertId": newID})
		svc, err := state.KubeClient.CoreV1().Services(ref.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			errs = append(errs, fmt.Sprintf("get service %s: %v", ref, err))
			continue
		}
		current := svc.Annotations[ccmCertificatesAnnotation]
		updated, replaced := replaceCertRefs(current, oldRefs, newID)
		if !replaced {
			l.WithField("annotation", current).Warn("service does not reference the previous certificate; not updating it")
			continue
		}
		patch, _ := json.Marshal(map[string]any{
			"metadata": map[string]any{"annotations": map[string]string{ccmCertificatesAnnotation: updated}},
		})
		if _, err := state.KubeClient.CoreV1().Services(ref.Namespace).Patch(ctx, ref.Name, k8stypes.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
			errs = append(errs, fmt.Sprintf("patch service %s: %v", ref, err))
			continue
		}
		l.WithField("annotation", updated).Info("service certificate annotation updated")
	}
	if len(errs) > 0 {
		return fmt.Errorf("updating services: %s", strings.Join(errs, "; "))
	}
	return nil
}

// deleteIfUnused deletes the certificate when no Load Balancer uses it. It
// returns true when the certificate is gone (deleted now or already absent).
func deleteIfUnused(ctx context.Context, client *hcloud.Client, id int64) (bool, error) {
	cert, _, err := client.Certificate.GetByID(ctx, id)
	if err != nil {
		return false, err
	}
	if cert == nil {
		return true, nil
	}
	if len(cert.UsedBy) > 0 {
		return false, nil
	}
	if _, err := client.Certificate.Delete(ctx, cert); err != nil {
		if hcloud.IsError(err, hcloud.ErrorCodeNotFound) {
			return true, nil
		}
		return false, err
	}
	return true, nil
}

// waitAndDelete polls until the certificate is released (the CCM reconciles
// the Service update within seconds) and deletes it. It returns false if the
// certificate is still in use after unusedPollTimeout.
func waitAndDelete(ctx context.Context, client *hcloud.Client, id int64) bool {
	l := log.WithFields(log.Fields{"store": "hetznercloud", "oldCertId": id})
	deadline := time.Now().Add(unusedPollTimeout)
	for {
		deleted, err := deleteIfUnused(ctx, client, id)
		if err != nil {
			l.WithError(err).Warn("failed to delete superseded certificate")
		}
		if deleted {
			l.Info("superseded certificate deleted")
			return true
		}
		if time.Now().After(deadline) {
			l.Warn("superseded certificate still in use; will retry on next sync")
			return false
		}
		time.Sleep(unusedPollInterval)
	}
}

// cleanupPending retries deleting certificates superseded by earlier syncs and
// returns the IDs that are still in use.
func cleanupPending(ctx context.Context, client *hcloud.Client, ids []int64) []int64 {
	var remaining []int64
	for _, id := range ids {
		deleted, err := deleteIfUnused(ctx, client, id)
		if err != nil {
			log.WithFields(log.Fields{"store": "hetznercloud", "oldCertId": id}).WithError(err).Warn("failed to delete superseded certificate")
		}
		if !deleted {
			remaining = append(remaining, id)
		}
	}
	return remaining
}
