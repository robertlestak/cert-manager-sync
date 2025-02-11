package digitalocean

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/digitalocean/godo"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	"github.com/robertlestak/cert-manager-sync/stores"
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

func New(c tlssecret.GenericSecretSyncConfig) (stores.RemoteStore, error) {
	var s = &DigitalOceanStore{}
	if c.Config["secret-name"] != "" {
		s.SecretName = c.Config["secret-name"]
	}
	if c.Config["secret-namespace"] != "" {
		s.SecretNamespace = c.Config["secret-namespace"]
	}
	// if secret name is in the format of "namespace/secretname" then parse it
	if strings.Contains(s.SecretName, "/") {
		if parts := strings.Split(s.SecretName, "/"); len(parts) == 2 {
			s.SecretNamespace = parts[0]
			s.SecretName = parts[1]
		}
	}
	if s.SecretName == "" {
		return nil, stores.ErrSecretNameNotFound
	}
	if s.SecretNamespace == "" {
		return nil, stores.ErrSecretNamespaceNotFound
	}
	if c.Config["cert-name"] != "" {
		s.CertName = c.Config["cert-name"]
	}
	if c.Config["cert-id"] != "" {
		s.CertId = c.Config["cert-id"]
	}

	return s, nil
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

func init() {
	stores.Register("digitalocean", stores.StoreCreatorFunc(New))
}
