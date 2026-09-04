package cloudflare

import (
	"context"
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
	// ModeOriginPull uploads an Authenticated Origin Pulls client certificate
	// that Cloudflare presents to the origin. It takes the leaf and the private
	// key only, and the issuing CA may be private.
	ModeOriginPull = "origin-pull"
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
		case ModeCustomCertificate, ModeOriginPull:
			s.Mode = c.Config["mode"]
		default:
			return fmt.Errorf("invalid mode %q: must be %q or %q", c.Config["mode"], ModeCustomCertificate, ModeOriginPull)
		}
	}
	// if secret name is in the format of "namespace/secretname" then parse it
	if strings.Contains(s.SecretName, "/") {
		s.SecretNamespace = strings.Split(s.SecretName, "/")[0]
		s.SecretName = strings.Split(s.SecretName, "/")[1]
	}
	return nil
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
	if s.Mode == ModeOriginPull {
		err = s.syncOriginPull(ctx, client, c, l)
	} else {
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
func (s *CloudflareStore) syncOriginPull(ctx context.Context, client *cloudflare.Client, c *tlssecret.Certificate, l *log.Entry) error {
	cert, err := client.OriginTLSClientAuth.New(ctx, origin_tls_client_auth.OriginTLSClientAuthNewParams{
		ZoneID:      cloudflare.F(s.ZoneId),
		Certificate: cloudflare.F(string(c.Certificate)),
		PrivateKey:  cloudflare.F(string(c.Key)),
	})
	if err != nil {
		l.WithError(err).Errorf("cloudflare.OriginTLSClientAuth.New error")
		return fmt.Errorf("failed to upload origin pull certificate to Cloudflare (zone: %s): %w", s.ZoneId, err)
	}
	replacedCertId := s.CertId
	s.CertId = cert.ID
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
	if s.Mode == ModeOriginPull {
		_, err = client.OriginTLSClientAuth.Delete(ctx, s.CertId, origin_tls_client_auth.OriginTLSClientAuthDeleteParams{
			ZoneID: cloudflare.F(s.ZoneId),
		})
	} else {
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
