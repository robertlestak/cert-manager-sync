package cloudflare

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/cloudflare/cloudflare-go/v5"
	"github.com/cloudflare/cloudflare-go/v5/custom_certificates"
	"github.com/cloudflare/cloudflare-go/v5/option"
	"github.com/cloudflare/cloudflare-go/v5/origin_tls_client_auth"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// ModeCustomCertificate uploads an edge certificate served to visitors.
	// Cloudflare must be able to bundle it against its own trust store, so the
	// certificate has to chain to a publicly trusted CA.
	ModeCustomCertificate = "custom-certificate"
	// ModeOriginPull uploads a zone-level Authenticated Origin Pulls client
	// certificate that Cloudflare presents to the origin. It takes the leaf and
	// the private key only, and the issuing CA may be private.
	ModeOriginPull = "origin-pull"
	// ModeOriginPullHostname is ModeOriginPull scoped to specific hostnames
	// instead of the whole zone. It requires Hostnames to be set, and takes
	// precedence over the zone-level certificate for those hostnames.
	ModeOriginPullHostname = "origin-pull-hostname"
)

type CloudflareStore struct {
	SecretName      string
	SecretNamespace string
	ApiToken        string
	ZoneId          string
	CertId          string
	// Mode selects which Cloudflare certificate store to sync to. An empty
	// value means ModeCustomCertificate.
	Mode string
	// Hostnames are the fully qualified domain names to associate the
	// certificate with, for ModeOriginPullHostname only.
	Hostnames []string
}

func (s *CloudflareStore) GetApiToken(ctx context.Context) error {
	gopt := metav1.GetOptions{}
	sc, err := state.KubeClient.CoreV1().Secrets(s.SecretNamespace).Get(ctx, s.SecretName, gopt)
	if err != nil {
		return fmt.Errorf("failed to get Cloudflare credentials secret %s/%s: %w", s.SecretNamespace, s.SecretName, err)
	}
	if sc.Data["api_token"] == nil {
		return fmt.Errorf("api_token not found in secret %s/%s", s.SecretNamespace, s.SecretName)
	}
	s.ApiToken = string(sc.Data["api_token"])
	return nil
}

func (s *CloudflareStore) FromConfig(c tlssecret.GenericSecretSyncConfig) error {
	l := log.WithFields(log.Fields{
		"action": "FromConfig",
	})
	l.Debugf("FromConfig")
	if c.Config["secret-name"] != "" {
		s.SecretName = c.Config["secret-name"]
	}
	if c.Config["secret-namespace"] != "" {
		s.SecretNamespace = c.Config["secret-namespace"]
	}
	if c.Config["zone-id"] != "" {
		s.ZoneId = c.Config["zone-id"]
	}
	if c.Config["cert-id"] != "" {
		s.CertId = c.Config["cert-id"]
	}
	if c.Config["mode"] != "" {
		switch c.Config["mode"] {
		case ModeCustomCertificate, ModeOriginPull, ModeOriginPullHostname:
			s.Mode = c.Config["mode"]
		default:
			return fmt.Errorf("invalid mode %q: must be one of %q, %q, %q", c.Config["mode"], ModeCustomCertificate, ModeOriginPull, ModeOriginPullHostname)
		}
	}
	if c.Config["hostnames"] != "" {
		s.Hostnames = parseHostnames(c.Config["hostnames"])
	}
	if s.Mode == ModeOriginPullHostname && len(s.Hostnames) == 0 {
		return fmt.Errorf("mode %q requires a non-empty hostnames list", ModeOriginPullHostname)
	}
	if len(s.Hostnames) > 0 && s.Mode != ModeOriginPullHostname {
		return fmt.Errorf("hostnames is only valid with mode %q", ModeOriginPullHostname)
	}
	// if secret name is in the format of "namespace/secretname" then parse it
	if strings.Contains(s.SecretName, "/") {
		s.SecretNamespace = strings.Split(s.SecretName, "/")[0]
		s.SecretName = strings.Split(s.SecretName, "/")[1]
	}
	return nil
}

// parseHostnames splits a comma separated hostname list, dropping blanks so a
// trailing comma or a padded value does not turn into an empty association.
func parseHostnames(v string) []string {
	var hostnames []string
	for _, h := range strings.Split(v, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hostnames = append(hostnames, h)
		}
	}
	return hostnames
}

func (s *CloudflareStore) setDefaultSecretNamespace(namespace string) {
	if s.SecretNamespace == "" {
		s.SecretNamespace = namespace
	}
}

func (s *CloudflareStore) Sync(c *tlssecret.Certificate) (map[string]string, error) {
	s.setDefaultSecretNamespace(c.Namespace)
	l := log.WithFields(log.Fields{
		"action":          "Sync",
		"store":           "cloudflare",
		"secretName":      s.SecretName,
		"secretNamespace": s.SecretNamespace,
	})
	l.Debugf("Update")
	if s.SecretName == "" {
		return nil, fmt.Errorf("secret name not found in certificate annotations")
	}
	ctx := context.Background()
	if err := s.GetApiToken(ctx); err != nil {
		l.WithError(err).Errorf("GetApiToken error")
		return nil, fmt.Errorf("failed to get Cloudflare API token from secret %s/%s: %w", s.SecretNamespace, s.SecretName, err)
	}
	client := cloudflare.NewClient(option.WithAPIToken(s.ApiToken))

	origCertId := s.CertId
	var err error
	switch s.Mode {
	case ModeOriginPull:
		err = s.syncOriginPull(ctx, client, c, l)
	case ModeOriginPullHostname:
		err = s.syncOriginPullHostname(ctx, client, c, l)
	default:
		err = s.syncCustomCertificate(ctx, client, c, l)
	}
	if err != nil {
		return nil, err
	}
	l = l.WithField("id", s.CertId)
	var newKeys map[string]string
	if origCertId != s.CertId {
		newKeys = map[string]string{
			"cert-id": s.CertId,
		}
	}
	l.Info("certificate synced")
	return newKeys, nil
}

// syncCustomCertificate uploads the full chain as an edge certificate,
// updating in place when a cert-id was recorded by a previous sync.
func (s *CloudflareStore) syncCustomCertificate(ctx context.Context, client *cloudflare.Client, c *tlssecret.Certificate, l *log.Entry) error {
	var cert *custom_certificates.CustomCertificate
	var err error
	if s.CertId != "" {
		// Update existing certificate
		cert, err = client.CustomCertificates.Edit(ctx, s.CertId, custom_certificates.CustomCertificateEditParams{
			ZoneID:      cloudflare.F(s.ZoneId),
			Certificate: cloudflare.F(string(c.FullChain())),
			PrivateKey:  cloudflare.F(string(c.Key)),
		})
		if err != nil {
			l.WithError(err).Errorf("cloudflare.CustomCertificates.Edit error")
			return fmt.Errorf("failed to update certificate in Cloudflare (zone: %s, cert: %s): %w", s.ZoneId, s.CertId, err)
		}
	} else {
		// Create new certificate
		cert, err = client.CustomCertificates.New(ctx, custom_certificates.CustomCertificateNewParams{
			ZoneID:      cloudflare.F(s.ZoneId),
			Certificate: cloudflare.F(string(c.FullChain())),
			PrivateKey:  cloudflare.F(string(c.Key)),
		})
		if err != nil {
			l.WithError(err).Errorf("cloudflare.CustomCertificates.New error")
			return fmt.Errorf("failed to create certificate in Cloudflare (zone: %s): %w", s.ZoneId, err)
		}
	}
	s.CertId = cert.ID
	return nil
}

// syncOriginPull uploads the leaf certificate and its key for Authenticated
// Origin Pulls. The CA certificate is deliberately left out: Cloudflare rejects
// anything but a leaf here. The API has no update method, so a renewal uploads
// a new certificate and then drops the one it replaced.
//
// A sync also runs when only the operator annotations changed (the certificate
// did not). Cloudflare refuses to upload the same certificate twice (error
// 1406), so the certificate already in the zone is reused instead.
func (s *CloudflareStore) syncOriginPull(ctx context.Context, client *cloudflare.Client, c *tlssecret.Certificate, l *log.Entry) error {
	certID, err := s.existingOriginPullCert(ctx, client, c)
	if err != nil {
		return err
	}
	if certID == "" {
		cert, err := client.OriginTLSClientAuth.New(ctx, origin_tls_client_auth.OriginTLSClientAuthNewParams{
			ZoneID:      cloudflare.F(s.ZoneId),
			Certificate: cloudflare.F(string(c.Certificate)),
			PrivateKey:  cloudflare.F(string(c.Key)),
		})
		if err != nil && isCloudflareErrorCode(err, cloudflareCodeCertificateExists) {
			// Uploaded by an earlier sync whose cert-id never made it back to
			// the secret: look it up.
			certID, err = s.findOriginPullCert(ctx, client, c)
			if err == nil && certID == "" {
				err = fmt.Errorf("cloudflare reports the certificate already exists but it is not listed in zone %s", s.ZoneId)
			}
		} else if err == nil {
			certID = cert.ID
		}
		if err != nil {
			l.WithError(err).Errorf("cloudflare.OriginTLSClientAuth.New error")
			return fmt.Errorf("failed to upload origin pull certificate to Cloudflare (zone: %s): %w", s.ZoneId, err)
		}
	} else {
		l.WithField("certId", certID).Debug("origin pull certificate already uploaded, reusing it")
	}
	replacedCertId := s.CertId
	s.CertId = certID
	if replacedCertId == "" || replacedCertId == s.CertId {
		return nil
	}
	if _, err := client.OriginTLSClientAuth.Delete(ctx, replacedCertId, origin_tls_client_auth.OriginTLSClientAuthDeleteParams{
		ZoneID: cloudflare.F(s.ZoneId),
	}); err != nil && !isCloudflareNotFound(err) {
		// The renewed certificate is already live, so a leftover certificate is
		// not worth failing (and retrying) the whole sync over.
		l.WithError(err).WithField("replacedId", replacedCertId).Warn("failed to remove replaced origin pull certificate")
	}
	return nil
}

// existingOriginPullCert returns s.CertId when the zone-level certificate it
// points at is the one being synced, and "" when a new upload is needed.
func (s *CloudflareStore) existingOriginPullCert(ctx context.Context, client *cloudflare.Client, c *tlssecret.Certificate) (string, error) {
	if s.CertId == "" {
		return "", nil
	}
	cert, err := client.OriginTLSClientAuth.Get(ctx, s.CertId, origin_tls_client_auth.OriginTLSClientAuthGetParams{
		ZoneID: cloudflare.F(s.ZoneId),
	})
	if err != nil {
		if isCloudflareNotFound(err) {
			return "", nil
		}
		return "", fmt.Errorf("failed to read origin pull certificate %s from Cloudflare (zone: %s): %w", s.CertId, s.ZoneId, err)
	}
	if sameCertificate(cert.Certificate, c.Certificate) {
		return s.CertId, nil
	}
	return "", nil
}

// findOriginPullCert looks for the zone-level certificate matching c.
func (s *CloudflareStore) findOriginPullCert(ctx context.Context, client *cloudflare.Client, c *tlssecret.Certificate) (string, error) {
	iter := client.OriginTLSClientAuth.ListAutoPaging(ctx, origin_tls_client_auth.OriginTLSClientAuthListParams{
		ZoneID: cloudflare.F(s.ZoneId),
	})
	for iter.Next() {
		if cert := iter.Current(); sameCertificate(cert.Certificate, c.Certificate) {
			return cert.ID, nil
		}
	}
	if err := iter.Err(); err != nil {
		return "", fmt.Errorf("failed to list origin pull certificates in Cloudflare (zone: %s): %w", s.ZoneId, err)
	}
	return "", nil
}

// syncOriginPullHostname uploads the leaf and key as a per-hostname
// Authenticated Origin Pulls certificate, then associates it with the
// configured hostnames. Like the zone-level endpoint it has no update method,
// so a renewal uploads a new certificate and drops the one it replaced.
//
// When the certificate is already uploaded (the sync was triggered by an
// annotation change, e.g. a new hostname), it is reused and only the
// association is updated: uploading it again fails with Cloudflare error 1406
// before the new hostnames are associated.
func (s *CloudflareStore) syncOriginPullHostname(ctx context.Context, client *cloudflare.Client, c *tlssecret.Certificate, l *log.Entry) error {
	certID, err := s.existingOriginPullHostnameCert(ctx, client, c)
	if err != nil {
		return err
	}
	uploaded := false
	if certID == "" {
		cert, err := client.OriginTLSClientAuth.Hostnames.Certificates.New(ctx, origin_tls_client_auth.HostnameCertificateNewParams{
			ZoneID:      cloudflare.F(s.ZoneId),
			Certificate: cloudflare.F(string(c.Certificate)),
			PrivateKey:  cloudflare.F(string(c.Key)),
		})
		if err != nil && isCloudflareErrorCode(err, cloudflareCodeCertificateExists) {
			// Uploaded by an earlier sync whose cert-id never made it back to
			// the secret: look it up.
			certID, err = s.findOriginPullHostnameCert(ctx, client, c)
			if err == nil && certID == "" {
				err = fmt.Errorf("cloudflare reports the certificate already exists but it is not listed in zone %s", s.ZoneId)
			}
		} else if err == nil {
			certID = cert.ID
			uploaded = true
		}
		if err != nil {
			l.WithError(err).Errorf("cloudflare.OriginTLSClientAuth.Hostnames.Certificates.New error")
			return fmt.Errorf("failed to upload per-hostname origin pull certificate to Cloudflare (zone: %s): %w", s.ZoneId, err)
		}
	} else {
		l.WithField("certId", certID).Debug("per-hostname origin pull certificate already uploaded, reusing it")
	}
	replacedCertId := s.CertId
	s.CertId = certID

	// Associating the hostnames is what puts the new certificate in use, so it
	// has to succeed before the one it replaces is removed.
	configs := make([]origin_tls_client_auth.HostnameUpdateParamsConfig, 0, len(s.Hostnames))
	for _, hostname := range s.Hostnames {
		configs = append(configs, origin_tls_client_auth.HostnameUpdateParamsConfig{
			CERTID:   cloudflare.F(s.CertId),
			Enabled:  cloudflare.F(true),
			Hostname: cloudflare.F(hostname),
		})
	}
	if _, err := client.OriginTLSClientAuth.Hostnames.Update(ctx, origin_tls_client_auth.HostnameUpdateParams{
		ZoneID: cloudflare.F(s.ZoneId),
		Config: cloudflare.F(configs),
	}); err != nil {
		l.WithError(err).Errorf("cloudflare.OriginTLSClientAuth.Hostnames.Update error")
		// A certificate uploaded by this sync is associated with nothing. Drop
		// it, otherwise every retry leaves another unused certificate behind.
		// A reused one may still serve the previous hostnames: keep it.
		if uploaded {
			if _, derr := client.OriginTLSClientAuth.Hostnames.Certificates.Delete(ctx, s.CertId, origin_tls_client_auth.HostnameCertificateDeleteParams{
				ZoneID: cloudflare.F(s.ZoneId),
			}); derr != nil && !isCloudflareNotFound(derr) {
				l.WithError(derr).WithField("certId", s.CertId).Warn("failed to remove unassociated origin pull certificate")
			}
			s.CertId = replacedCertId
		}
		return fmt.Errorf("failed to associate hostnames [%s] with certificate %s (zone: %s): %w", strings.Join(s.Hostnames, ", "), certID, s.ZoneId, err)
	}

	if replacedCertId == "" || replacedCertId == s.CertId {
		return nil
	}
	if _, err := client.OriginTLSClientAuth.Hostnames.Certificates.Delete(ctx, replacedCertId, origin_tls_client_auth.HostnameCertificateDeleteParams{
		ZoneID: cloudflare.F(s.ZoneId),
	}); err != nil && !isCloudflareNotFound(err) {
		// The renewed certificate is already associated, so a leftover
		// certificate is not worth failing (and retrying) the whole sync over.
		l.WithError(err).WithField("replacedId", replacedCertId).Warn("failed to remove replaced per-hostname origin pull certificate")
	}
	return nil
}

// existingOriginPullHostnameCert returns s.CertId when the per-hostname
// certificate it points at is the one being synced, and "" when a new upload
// is needed.
func (s *CloudflareStore) existingOriginPullHostnameCert(ctx context.Context, client *cloudflare.Client, c *tlssecret.Certificate) (string, error) {
	if s.CertId == "" {
		return "", nil
	}
	cert, err := client.OriginTLSClientAuth.Hostnames.Certificates.Get(ctx, s.CertId, origin_tls_client_auth.HostnameCertificateGetParams{
		ZoneID: cloudflare.F(s.ZoneId),
	})
	if err != nil {
		if isCloudflareNotFound(err) {
			return "", nil
		}
		return "", fmt.Errorf("failed to read per-hostname origin pull certificate %s from Cloudflare (zone: %s): %w", s.CertId, s.ZoneId, err)
	}
	if sameCertificate(cert.Certificate, c.Certificate) {
		return s.CertId, nil
	}
	return "", nil
}

// findOriginPullHostnameCert looks for the per-hostname certificate matching c.
func (s *CloudflareStore) findOriginPullHostnameCert(ctx context.Context, client *cloudflare.Client, c *tlssecret.Certificate) (string, error) {
	iter := client.OriginTLSClientAuth.Hostnames.Certificates.ListAutoPaging(ctx, origin_tls_client_auth.HostnameCertificateListParams{
		ZoneID: cloudflare.F(s.ZoneId),
	})
	for iter.Next() {
		if cert := iter.Current(); sameCertificate(cert.Certificate, c.Certificate) {
			return cert.ID, nil
		}
	}
	if err := iter.Err(); err != nil {
		return "", fmt.Errorf("failed to list per-hostname origin pull certificates in Cloudflare (zone: %s): %w", s.ZoneId, err)
	}
	return "", nil
}

// sameCertificate reports whether two PEM documents hold the same leaf
// certificate. Cloudflare may return the PEM re-encoded, so the first
// CERTIFICATE blocks are compared as DER.
func sameCertificate(a string, b []byte) bool {
	da, db := firstCertificateDER([]byte(a)), firstCertificateDER(b)
	return da != nil && db != nil && bytes.Equal(da, db)
}

func firstCertificateDER(data []byte) []byte {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil
		}
		if block.Type == "CERTIFICATE" {
			return block.Bytes
		}
	}
}

// cloudflareCodeCertificateExists is returned when uploading a certificate the
// zone already has ("This certificate already exists for this zone.").
const cloudflareCodeCertificateExists = 1406

// isCloudflareErrorCode reports whether err is a Cloudflare API error carrying
// the given error code.
func isCloudflareErrorCode(err error, code int64) bool {
	var cfErr *cloudflare.Error
	if !errors.As(err, &cfErr) {
		return false
	}
	for _, e := range cfErr.Errors {
		if e.Code == code {
			return true
		}
	}
	return false
}

// isCloudflareNotFound returns true when the error reports a 404 from the
// Cloudflare API.
func isCloudflareNotFound(err error) bool {
	if err == nil {
		return false
	}
	var cfErr *cloudflare.Error
	if errors.As(err, &cfErr) {
		return cfErr.StatusCode == 404
	}
	return false
}

// Delete removes the certificate from Cloudflare. 404 responses are treated as
// success so the operation is idempotent.
func (s *CloudflareStore) Delete(ctx context.Context) error {
	l := log.WithFields(log.Fields{
		"action":  "cloudflare.Delete",
		"id":      s.CertId,
		"zone-id": s.ZoneId,
		"mode":    s.Mode,
	})
	if s.CertId == "" {
		// Sync never populated cert-id, so there is no remote certificate
		// to clean up. Treat as success so opt-in secrets that failed their
		// initial sync are not wedged on deletion.
		l.Debug("no cloudflare cert-id recorded; nothing to delete")
		return nil
	}
	if s.ZoneId == "" {
		return fmt.Errorf("cloudflare zone-id not set; cannot delete %s", s.CertId)
	}
	if s.SecretName == "" {
		return fmt.Errorf("cloudflare secret-name not set; cannot resolve API token for delete")
	}
	if err := s.GetApiToken(ctx); err != nil {
		return fmt.Errorf("cloudflare credentials lookup failed: %w", err)
	}
	client := cloudflare.NewClient(option.WithAPIToken(s.ApiToken))
	var err error
	switch s.Mode {
	case ModeOriginPull:
		_, err = client.OriginTLSClientAuth.Delete(ctx, s.CertId, origin_tls_client_auth.OriginTLSClientAuthDeleteParams{
			ZoneID: cloudflare.F(s.ZoneId),
		})
	case ModeOriginPullHostname:
		_, err = client.OriginTLSClientAuth.Hostnames.Certificates.Delete(ctx, s.CertId, origin_tls_client_auth.HostnameCertificateDeleteParams{
			ZoneID: cloudflare.F(s.ZoneId),
		})
	default:
		_, err = client.CustomCertificates.Delete(ctx, s.CertId, custom_certificates.CustomCertificateDeleteParams{
			ZoneID: cloudflare.F(s.ZoneId),
		})
	}
	if err != nil {
		if isCloudflareNotFound(err) {
			l.Debug("cloudflare certificate already absent; treating delete as success")
			return nil
		}
		return fmt.Errorf("delete Cloudflare certificate %s (zone %s): %w", s.CertId, s.ZoneId, err)
	}
	l.Info("certificate deleted from cloudflare")
	return nil
}
