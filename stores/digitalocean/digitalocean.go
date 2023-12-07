package digitalocean

import (
	"context"
	"fmt"
	"strings"

	"github.com/digitalocean/godo"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	corev1 "k8s.io/api/core/v1"
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

func (s *DigitalOceanStore) ParseCertificate(c *tlssecret.Certificate) error {
	l := log.WithFields(log.Fields{
		"action": "ParseCertificate",
	})
	l.Debugf("ParseCertificate")
	if c.Annotations[state.OperatorName+"/digitalocean-secret-name"] != "" {
		s.SecretName = c.Annotations[state.OperatorName+"/digitalocean-secret-name"]
	}
	if c.Annotations[state.OperatorName+"/digitalocean-cert-name"] != "" {
		s.CertName = c.Annotations[state.OperatorName+"/digitalocean-cert-name"]
	}
	if c.Annotations[state.OperatorName+"/digitalocean-cert-id"] != "" {
		s.CertId = c.Annotations[state.OperatorName+"/digitalocean-cert-id"]
	}
	// if secret name is in the format of "namespace/secretname" then parse it
	if strings.Contains(s.SecretName, "/") {
		s.SecretNamespace = strings.Split(s.SecretName, "/")[0]
		s.SecretName = strings.Split(s.SecretName, "/")[1]
	}
	return nil
}

func separateCertsDO(crt, key []byte) *godo.CertificateRequest {
	b := "-----BEGIN CERTIFICATE-----\n"
	str := strings.Split(string(crt), b)
	nc := b + str[1]
	ch := b + strings.Join(str[2:], b)
	im := &godo.CertificateRequest{
		CertificateChain: string(ch),
		LeafCertificate:  string(nc),
		PrivateKey:       string(key),
	}
	return im
}

func (s *DigitalOceanStore) Update(secret *corev1.Secret) error {
	l := log.WithFields(log.Fields{
		"action":          "Update",
		"store":           "digitalocean",
		"certName":        s.CertName,
		"secretName":      secret.ObjectMeta.Name,
		"secretNamespace": secret.ObjectMeta.Namespace,
	})
	l.Debugf("Update")
	c := tlssecret.ParseSecret(secret)
	if err := s.ParseCertificate(c); err != nil {
		l.WithError(err).Errorf("ParseCertificate error")
		return err
	}
	if s.SecretNamespace == "" {
		s.SecretNamespace = secret.Namespace
	}
	if s.SecretName == "" {
		return fmt.Errorf("secret name not found in certificate annotations")
	}
	ctx := context.Background()
	if err := s.GetApiKey(ctx); err != nil {
		l.WithError(err).Errorf("GetApiKey error")
		return err
	}
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: s.ApiKey})
	oauthClient := oauth2.NewClient(context.Background(), tokenSource)
	client := godo.NewClient(oauthClient)
	certRequest := separateCertsDO(c.Certificate, c.Key)
	certRequest.Name = s.CertName
	origCertId := s.CertId
	if s.CertId != "" {
		l.WithField("id", s.CertId).Debugf("deleting certificate")
		_, err := client.Certificates.Delete(context.Background(), s.CertId)
		if err != nil {
			l.WithError(err).Errorf("cannot delete certificate")
			return err
		}
		l.WithField("id", s.CertId).Debugf("certificate deleted")
	}
	certificate, _, err := client.Certificates.Create(context.Background(), certRequest)
	if err != nil {
		l.WithError(err).Errorf("cannot create certificate")
		return err
	}
	l.WithField("name", certificate.ID).Debugf("certificate created")
	s.CertId = certificate.ID
	if origCertId != s.CertId {
		secret.ObjectMeta.Annotations[state.OperatorName+"/digitalocean-cert-id"] = s.CertId
		sc := state.KubeClient.CoreV1().Secrets(secret.ObjectMeta.Namespace)
		uo := metav1.UpdateOptions{}
		_, uerr := sc.Update(
			context.Background(),
			secret,
			uo,
		)
		if uerr != nil {
			l.WithError(uerr).Errorf("secret.Update error")
			return uerr
		}
	}
	l.Info("certificate synced")
	return nil
}
