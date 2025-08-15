package cloudflare

import (
	"context"
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
		return err
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
		return nil, err
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
			return nil, err
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
			return nil, err
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
