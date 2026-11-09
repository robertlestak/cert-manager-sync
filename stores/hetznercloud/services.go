package hetznercloud

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
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

// ownerLabel marks every certificate this store uploads with a hash of the
// source secret and certificate name, so superseded or orphaned copies (for
// example from a sync interrupted by a restart) can be found and cleaned up.
const ownerLabel = "cert-manager-sync.lestak.sh/owner"

// Superseded certificates still attached to a Load Balancer are retried in the
// background, so a sync never blocks waiting for the CCM to detach them.
// Overridden in tests.
var (
	detachRetryTimeout  = 5 * time.Minute
	detachRetryInterval = 10 * time.Second
	backgroundCleanups  sync.WaitGroup
)

func ownerValue(namespace, secretName, certName string) string {
	sum := sha256.Sum256([]byte(namespace + "/" + secretName + "/" + certName))
	return hex.EncodeToString(sum[:])[:40]
}

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

// pointCertRefs makes a comma-separated certificate list reference newID: any
// entry naming one of staleRefs (IDs or names of certificates this store
// replaced) is swapped for newID, and newID is appended if it isn't listed yet.
// Entries for unrelated certificates (e.g. other SNI hostnames) are kept.
func pointCertRefs(annotation string, staleRefs []string, newID int64) string {
	newRef := strconv.FormatInt(newID, 10)
	stale := map[string]bool{}
	for _, r := range staleRefs {
		if r != "" {
			stale[r] = true
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, e := range strings.Split(annotation, ",") {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if stale[e] {
			e = newRef
		}
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	if !seen[newRef] {
		out = append(out, newRef)
	}
	return strings.Join(out, ",")
}

// ensureServices makes each listed Service reference the current certificate,
// covering the first attach, renewals under a new name, and drift.
func (s *HetznerCloudStore) ensureServices(ctx context.Context, staleRefs []string, newID int64) error {
	var errs []string
	for _, ref := range s.Services {
		l := log.WithFields(log.Fields{"store": "hetznercloud", "service": ref.String(), "certId": newID})
		svc, err := state.KubeClient.CoreV1().Services(ref.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			errs = append(errs, fmt.Sprintf("get service %s: %v", ref, err))
			continue
		}
		current := svc.Annotations[ccmCertificatesAnnotation]
		updated := pointCertRefs(current, staleRefs, newID)
		if updated == current {
			continue
		}
		patch, _ := json.Marshal(map[string]any{
			"metadata": map[string]any{
				"resourceVersion": svc.ResourceVersion,
				"annotations":     map[string]string{ccmCertificatesAnnotation: updated},
			},
		})
		if _, err := state.KubeClient.CoreV1().Services(ref.Namespace).Patch(ctx, ref.Name, k8stypes.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
			errs = append(errs, fmt.Sprintf("patch service %s: %v", ref, err))
			continue
		}
		l.WithFields(log.Fields{"from": current, "to": updated}).Info("service certificate annotation updated")
	}
	if len(errs) > 0 {
		return fmt.Errorf("updating services: %s", strings.Join(errs, "; "))
	}
	return nil
}

// ownedCertificates lists the certificates carrying this sync's owner label.
func ownedCertificates(ctx context.Context, client *hcloud.Client, owner string) ([]*hcloud.Certificate, error) {
	return client.Certificate.AllWithOpts(ctx, hcloud.CertificateListOpts{
		ListOpts: hcloud.ListOpts{LabelSelector: ownerLabel + "=" + owner},
	})
}

// deleteUnused deletes the given certificates that no Load Balancer uses and
// returns the ones that are still attached.
func deleteUnused(ctx context.Context, client *hcloud.Client, certs []*hcloud.Certificate) []*hcloud.Certificate {
	var attached []*hcloud.Certificate
	for _, c := range certs {
		l := log.WithFields(log.Fields{"store": "hetznercloud", "certId": c.ID, "certName": c.Name})
		fresh, _, err := client.Certificate.GetByID(ctx, c.ID)
		if err != nil {
			l.WithError(err).Warn("failed to read superseded certificate")
			attached = append(attached, c)
			continue
		}
		if fresh == nil {
			continue
		}
		if len(fresh.UsedBy) > 0 {
			attached = append(attached, fresh)
			continue
		}
		if _, err := client.Certificate.Delete(ctx, fresh); err != nil && !hcloud.IsError(err, hcloud.ErrorCodeNotFound) {
			l.WithError(err).Warn("failed to delete superseded certificate")
			attached = append(attached, fresh)
			continue
		}
		l.Info("superseded certificate deleted")
	}
	return attached
}

// retryDetached keeps trying to delete certificates that were still attached,
// giving the CCM time to move the Load Balancer to the new certificate. Anything
// left after detachRetryTimeout is picked up by the next sync of the secret.
func retryDetached(client *hcloud.Client, certs []*hcloud.Certificate) {
	if len(certs) == 0 {
		return
	}
	backgroundCleanups.Add(1)
	go func() {
		defer backgroundCleanups.Done()
		ctx := context.Background()
		deadline := time.Now().Add(detachRetryTimeout)
		for len(certs) > 0 && time.Now().Before(deadline) {
			time.Sleep(detachRetryInterval)
			certs = deleteUnused(ctx, client, certs)
		}
		for _, c := range certs {
			log.WithFields(log.Fields{"store": "hetznercloud", "certId": c.ID, "certName": c.Name}).
				Warn("superseded certificate still attached; it will be retried on the next sync")
		}
	}()
}
