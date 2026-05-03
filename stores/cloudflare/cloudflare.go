package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/cloudflare/cloudflare-go/v5"
	"github.com/cloudflare/cloudflare-go/v5/custom_certificates"
	"github.com/cloudflare/cloudflare-go/v5/option"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type CloudflareStore struct {
	SecretName      string
	SecretNamespace string
	ApiToken        string
	ZoneId          string
	CertId          string
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
	// if secret name is in the format of "namespace/secretname" then parse it
	if strings.Contains(s.SecretName, "/") {
		s.SecretNamespace = strings.Split(s.SecretName, "/")[0]
		s.SecretName = strings.Split(s.SecretName, "/")[1]
	}
	return nil
}

func (s *CloudflareStore) Sync(c *tlssecret.Certificate) (map[string]string, error) {
	s.SecretNamespace = c.Namespace
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
			return nil, fmt.Errorf("failed to update certificate in Cloudflare (zone: %s, cert: %s): %w", s.ZoneId, s.CertId, err)
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
			return nil, fmt.Errorf("failed to create certificate in Cloudflare (zone: %s): %w", s.ZoneId, err)
		}
	}
	s.CertId = cert.ID
	l = l.WithField("id", cert.ID)
	var newKeys map[string]string
	if origCertId != s.CertId {
		newKeys = map[string]string{
			"cert-id": s.CertId,
		}
	}
	l.Info("certificate synced")
	return newKeys, nil
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

// Delete removes the custom certificate from Cloudflare. 404 responses are
// treated as success so the operation is idempotent.
func (s *CloudflareStore) Delete(ctx context.Context) error {
	l := log.WithFields(log.Fields{
		"action":  "cloudflare.Delete",
		"id":      s.CertId,
		"zone-id": s.ZoneId,
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
	if _, err := client.CustomCertificates.Delete(ctx, s.CertId, custom_certificates.CustomCertificateDeleteParams{
		ZoneID: cloudflare.F(s.ZoneId),
	}); err != nil {
		if isCloudflareNotFound(err) {
			l.Debug("cloudflare certificate already absent; treating delete as success")
			return nil
		}
		return fmt.Errorf("delete Cloudflare certificate %s (zone %s): %w", s.CertId, s.ZoneId, err)
	}
	l.Info("certificate deleted from cloudflare")
	return nil
}
