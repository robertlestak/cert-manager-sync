package digitalocean

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/digitalocean/godo"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type DigitalOceanStore struct {
	SecretName      string
	SecretNamespace string
	ApiKey          string
	CertName        string
	CertId          string
}

func (s *DigitalOceanStore) GetApiKey(ctx context.Context) error {
	gopt := metav1.GetOptions{}
	sc, err := state.KubeClient.CoreV1().Secrets(s.SecretNamespace).Get(ctx, s.SecretName, gopt)
	if err != nil {
		return err
	}
	if sc.Data["api_key"] == nil {
		return fmt.Errorf("api_key not found in secret %s/%s", s.SecretNamespace, s.SecretName)
	}
	s.ApiKey = string(sc.Data["api_key"])
	return nil
}

func (s *DigitalOceanStore) FromConfig(c tlssecret.GenericSecretSyncConfig) error {
	l := log.WithFields(log.Fields{
		"action": "FromConfig",
	})
	l.Debugf("FromConfig")
	if c.Config["secret-name"] != "" {
		s.SecretName = c.Config["secret-name"]
	}
	if c.Config["cert-name"] != "" {
		s.CertName = c.Config["cert-name"]
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

func separateCertsDO(ca, crt, key []byte) *godo.CertificateRequest {
	re := regexp.MustCompile(`(?s)(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)`)
	certBlocks := re.FindAllString(string(crt), -1)
	if len(certBlocks) == 0 {
		return nil
	}
	nc := certBlocks[0]
	ch := strings.Join(certBlocks[1:], "\n")
	if len(ca) > 0 {
		ch += "\n" + string(ca)
	}
	im := &godo.CertificateRequest{
		CertificateChain: ch,
		LeafCertificate:  nc,
		PrivateKey:       string(key),
	}
	return im
}

func (s *DigitalOceanStore) Sync(c *tlssecret.Certificate) (map[string]string, error) {
	s.SecretNamespace = c.Namespace
	l := log.WithFields(log.Fields{
		"action":          "Update",
		"store":           "digitalocean",
		"certName":        s.CertName,
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
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: s.ApiKey})
	oauthClient := oauth2.NewClient(context.Background(), tokenSource)
	client := godo.NewClient(oauthClient)
	certRequest := separateCertsDO(c.Ca, c.Certificate, c.Key)
	certRequest.Name = s.CertName
	origCertId := s.CertId
	if s.CertId != "" {
		l.WithField("id", s.CertId).Debugf("deleting certificate")
		_, err := client.Certificates.Delete(context.Background(), s.CertId)
		if err != nil {
			l.WithError(err).Errorf("cannot delete certificate")
			return nil, err
		}
		l.WithField("id", s.CertId).Debugf("certificate deleted")
	}
	certificate, _, err := client.Certificates.Create(context.Background(), certRequest)
	if err != nil {
		l.WithError(err).Errorf("cannot create certificate")
		return nil, err
	}
	l = l.WithField("id", certificate.ID)
	s.CertId = certificate.ID
	var newKeys map[string]string
	if origCertId != s.CertId {
		newKeys = map[string]string{
			"cert-id": s.CertId,
		}
	}
	l.Info("certificate synced")
	return newKeys, nil
}
