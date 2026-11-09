package hetznercloud

import (
	"context"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
)

type HetznerCloudStore struct {
	SecretName      string
	SecretNamespace string
	ApiToken        string
	CertName        string
	CertId          int64
	Labels          map[string]string
	// ServicesRaw lists Kubernetes Services ("ns/name,...") whose
	// load-balancer.hetzner.cloud/http-certificates annotation should follow
	// the certificate when it has to be re-created under a new name.
	ServicesRaw string
	Services    []k8stypes.NamespacedName
}

func (s *HetznerCloudStore) GetApiToken(ctx context.Context) error {
	gopt := metav1.GetOptions{}
	sc, err := state.KubeClient.CoreV1().Secrets(s.SecretNamespace).Get(ctx, s.SecretName, gopt)
	if err != nil {
		return fmt.Errorf("failed to get Hetzner Cloud credentials secret %s/%s: %w", s.SecretNamespace, s.SecretName, err)
	}
	if sc.Data["api_token"] == nil && sc.Data["token"] == nil {
		return fmt.Errorf("api_token or token not found in secret %s/%s", s.SecretNamespace, s.SecretName)
	}
	// Support both "api_token" and "token" for compatibility
	if sc.Data["api_token"] != nil {
		s.ApiToken = string(sc.Data["api_token"])
	} else {
		s.ApiToken = string(sc.Data["token"])
	}
	return nil
}

func (s *HetznerCloudStore) FromConfig(c tlssecret.GenericSecretSyncConfig) error {
	l := log.WithFields(log.Fields{
		"action": "FromConfig",
		"store":  "hetznercloud",
	})
	l.Debugf("FromConfig")

	if c.Config["secret-name"] != "" {
		s.SecretName = c.Config["secret-name"]
	}
	if c.Config["cert-name"] != "" {
		s.CertName = c.Config["cert-name"]
	}
	if c.Config["cert-id"] != "" {
		certId, err := strconv.ParseInt(c.Config["cert-id"], 10, 64)
		if err != nil {
			l.WithError(err).Errorf("failed to parse cert-id")
			return fmt.Errorf("failed to parse Hetzner Cloud cert-id '%s': %w", c.Config["cert-id"], err)
		}
		s.CertId = certId
	}

	s.ServicesRaw = c.Config["services"]

	// Parse labels if provided
	s.Labels = make(map[string]string)
	for k, v := range c.Config {
		if strings.HasPrefix(k, "label-") {
			labelKey := strings.TrimPrefix(k, "label-")
			s.Labels[labelKey] = v
		}
	}

	// if secret name is in the format of "namespace/secretname" then parse it
	if strings.Contains(s.SecretName, "/") {
		s.SecretNamespace = strings.Split(s.SecretName, "/")[0]
		s.SecretName = strings.Split(s.SecretName, "/")[1]
	}

	return nil
}

func (s *HetznerCloudStore) Sync(c *tlssecret.Certificate) (map[string]string, error) {
	if s.SecretNamespace == "" {
		s.SecretNamespace = c.Namespace
	}
	if s.ServicesRaw != "" {
		refs, err := parseServiceRefs(s.ServicesRaw, c.Namespace)
		if err != nil {
			return nil, err
		}
		s.Services = refs
	}
	l := log.WithFields(log.Fields{
		"action":          "Update",
		"store":           "hetznercloud",
		"certName":        s.CertName,
		"secretName":      s.SecretName,
		"secretNamespace": s.SecretNamespace,
	})
	l.Debugf("Update")

	if s.SecretName == "" && s.ApiToken == "" {
		return nil, fmt.Errorf("secret name not found in certificate annotations")
	}

	ctx := context.Background()
	// Only get API token from K8s secret if not already set (e.g., for testing)
	if s.ApiToken == "" {
		if err := s.GetApiToken(ctx); err != nil {
			l.WithError(err).Errorf("GetApiToken error")
			return nil, err
		}
	}

	// Create Hetzner Cloud client
	client := hcloud.NewClient(hcloud.WithToken(s.ApiToken))

	// Prepare certificate name - use provided name or use secret name
	certName := s.CertName
	if certName == "" {
		certName = c.SecretName
	}

	origCertId := s.CertId
	owner := ownerValue(c.Namespace, c.SecretName, certName)
	labels := map[string]string{ownerLabel: owner}
	for k, v := range s.Labels {
		labels[k] = v
	}

	// Everything this sync uploaded before, plus the recorded certificate if it
	// predates owner labels. All of it is superseded once the new one exists.
	superseded, err := ownedCertificates(ctx, client, owner)
	if err != nil {
		l.WithError(err).Warn("failed to list previously uploaded certificates")
	}
	if s.CertId != 0 && !containsCert(superseded, s.CertId) {
		existing, _, err := client.Certificate.GetByID(ctx, s.CertId)
		if err != nil {
			l.WithError(err).Warnf("failed to get existing certificate, it may have been deleted")
		} else if existing != nil {
			superseded = append(superseded, existing)
		}
	}

	// Adopt a recorded certificate uploaded before owner labels existed, so it
	// stays tracked (and is cleaned up later) even if it can't be deleted now.
	for _, old := range superseded {
		if old.Labels[ownerLabel] != owner {
			if updated, _, err := client.Certificate.Update(ctx, old, hcloud.CertificateUpdateOpts{Labels: mergeLabels(old.Labels, labels)}); err != nil {
				l.WithError(err).WithField("certId", old.ID).Warn("failed to label existing certificate")
			} else if updated != nil {
				old.Labels = updated.Labels
			}
		}
	}

	// Hetzner Cloud rejects uploading the same certificate twice. If an earlier
	// copy already holds this exact certificate (e.g. a re-sync after only the
	// annotations changed), keep using it instead of uploading.
	var cert *hcloud.Certificate
	if fp, err := leafFingerprint(c.Certificate); err == nil {
		for i, old := range superseded {
			if strings.EqualFold(old.Fingerprint, fp) {
				cert = old
				superseded = append(superseded[:i:i], superseded[i+1:]...)
				break
			}
		}
	}

	var staleRefs []string
	for _, old := range superseded {
		staleRefs = append(staleRefs, strconv.FormatInt(old.ID, 10), old.Name)
	}

	// Hetzner Cloud certificates can't be updated in place. Free the name by
	// deleting unused copies first; if one holding the name is still attached
	// to a Load Balancer, upload under a new name instead.
	superseded = deleteUnused(ctx, client, superseded)

	if cert != nil {
		l.WithField("id", cert.ID).Debug("certificate already uploaded, reusing it")
	} else {
		for holder := certHolder(superseded, certName); holder != nil; holder = certHolder(superseded, certName) {
			l.Warnf("certificate %d is in use by %d resources, uploading under a new name", holder.ID, len(holder.UsedBy))
			certName = fmt.Sprintf("%s-%d", certName, holder.ID)
		}

		createOpts := hcloud.CertificateCreateOpts{
			Name:        certName,
			Type:        hcloud.CertificateTypeUploaded,
			Certificate: string(c.Certificate),
			PrivateKey:  string(c.Key),
			Labels:      labels,
		}

		l.WithField("name", certName).Debugf("creating new certificate")
		cert, _, err = client.Certificate.Create(ctx, createOpts)
		if err != nil {
			l.WithError(err).Errorf("failed to create certificate")
			return nil, err
		}
	}

	l = l.WithField("id", cert.ID)
	s.CertId = cert.ID

	if len(s.Services) > 0 {
		// A reference to the current certificate by name becomes its ID too.
		staleRefs = append(staleRefs, cert.Name)
		if err := s.ensureServices(ctx, staleRefs, cert.ID); err != nil {
			// Fail the sync so it is retried; the certificate uploaded here is
			// owner-labelled and gets replaced by the retry.
			return nil, err
		}
	}
	retryDetached(client, superseded)

	newKeys := map[string]string{}
	if origCertId != s.CertId {
		newKeys["cert-id"] = strconv.FormatInt(s.CertId, 10)
	}

	l.Info("certificate synced")
	return newKeys, nil
}

// Delete removes the certificate from Hetzner Cloud. NotFound responses are
// treated as success so the operation is idempotent.
func (s *HetznerCloudStore) Delete(ctx context.Context) error {
	l := log.WithFields(log.Fields{
		"action": "hetznercloud.Delete",
		"id":     s.CertId,
	})
	if s.CertId == 0 {
		// Sync never populated cert-id, so there is no remote certificate
		// to clean up. Treat as success so opt-in secrets that failed their
		// initial sync are not wedged on deletion.
		l.Debug("no hetznercloud cert-id recorded; nothing to delete")
		return nil
	}
	if s.ApiToken == "" {
		if s.SecretName == "" {
			return fmt.Errorf("hetznercloud secret-name not set; cannot resolve API token for delete")
		}
		if err := s.GetApiToken(ctx); err != nil {
			return fmt.Errorf("hetznercloud credentials lookup failed: %w", err)
		}
	}
	client := hcloud.NewClient(hcloud.WithToken(s.ApiToken))
	if _, err := client.Certificate.Delete(ctx, &hcloud.Certificate{ID: s.CertId}); err != nil {
		if hcloud.IsError(err, hcloud.ErrorCodeNotFound) {
			l.Debug("hetznercloud certificate already absent; treating delete as success")
			return nil
		}
		return fmt.Errorf("delete Hetzner certificate %d: %w", s.CertId, err)
	}
	l.Info("certificate deleted from hetznercloud")
	return nil
}

// leafFingerprint returns the SHA-256 fingerprint of the first certificate in
// a PEM bundle, in the colon-separated form Hetzner Cloud reports.
func leafFingerprint(pemBundle []byte) (string, error) {
	block, _ := pem.Decode(pemBundle)
	if block == nil {
		return "", fmt.Errorf("no PEM block found")
	}
	sum := sha256.Sum256(block.Bytes)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":"), nil
}

func mergeLabels(base, extra map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func certHolder(certs []*hcloud.Certificate, name string) *hcloud.Certificate {
	for _, c := range certs {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func containsCert(certs []*hcloud.Certificate, id int64) bool {
	for _, c := range certs {
		if c.ID == id {
			return true
		}
	}
	return false
}
