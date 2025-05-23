package cloudflare

import (
	"context"
	"fmt"
	"strings"

	"github.com/cloudflare/cloudflare-go"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type CloudflareStore struct {
	SecretName      string
	SecretNamespace string
	ApiKey          string
	ApiEmail        string
	ZoneId          string
	CertId          string
}

func (s *CloudflareStore) GetApiKey(ctx context.Context) error {
	gopt := metav1.GetOptions{}
	sc, err := state.KubeClient.CoreV1().Secrets(s.SecretNamespace).Get(ctx, s.SecretName, gopt)
	if err != nil {
		return err
	}
	if sc.Data["api_key"] == nil {
		return fmt.Errorf("api_key not found in secret %s/%s", s.SecretNamespace, s.SecretName)
	}
	if sc.Data["email"] == nil {
		return fmt.Errorf("email not found in secret %s/%s", s.SecretNamespace, s.SecretName)
	}
	s.ApiKey = string(sc.Data["api_key"])
	s.ApiEmail = string(sc.Data["email"])
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
	if err := s.GetApiKey(ctx); err != nil {
		l.WithError(err).Errorf("GetApiKey error")
		return nil, err
	}
	client, err := cloudflare.New(s.ApiKey, s.ApiEmail)
	if err != nil {
		l.WithError(err).Errorf("cloudflare.New error")
		return nil, err
	}
	certRequest := cloudflare.ZoneCustomSSLOptions{
		Certificate: string(c.FullChain()),
		PrivateKey:  string(c.Key),
	}
	origCertId := s.CertId
	var sslCert cloudflare.ZoneCustomSSL
	if s.CertId != "" {
		sslCert, err = client.UpdateSSL(context.Background(), s.ZoneId, s.CertId, certRequest)
		if err != nil {
			l.WithError(err).Errorf("cloudflare.UpdateZoneCustomSSL error")
			return nil, err
		}
	} else {
		sslCert, err = client.CreateSSL(context.Background(), s.ZoneId, certRequest)
		if err != nil {
			l.WithError(err).Errorf("cloudflare.CreateZoneCustomSSL error")
			return nil, err
		}
	}
	s.CertId = sslCert.ID
	l = l.WithField("id", sslCert.ID)
	var newKeys map[string]string
	if origCertId != s.CertId {
		newKeys = map[string]string{
			"cert-id": s.CertId,
		}
	}
	l.Info("certificate synced")
	return newKeys, nil
}
