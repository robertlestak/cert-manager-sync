package cloudflare

import (
	"context"
	"fmt"
	"strings"

	"github.com/cloudflare/cloudflare-go"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
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

func (s *CloudflareStore) ParseCertificate(c *tlssecret.Certificate) error {
	l := log.WithFields(log.Fields{
		"action": "ParseCertificate",
	})
	l.Debugf("ParseCertificate")
	if c.Annotations[state.OperatorName+"/cloudflare-secret-name"] != "" {
		s.SecretName = c.Annotations[state.OperatorName+"/cloudflare-secret-name"]
	}
	if c.Annotations[state.OperatorName+"/cloudflare-zone-id"] != "" {
		s.ZoneId = c.Annotations[state.OperatorName+"/cloudflare-zone-id"]
	}
	if c.Annotations[state.OperatorName+"/cloudflare-cert-id"] != "" {
		s.CertId = c.Annotations[state.OperatorName+"/cloudflare-cert-id"]
	}
	// if secret name is in the format of "namespace/secretname" then parse it
	if strings.Contains(s.SecretName, "/") {
		s.SecretNamespace = strings.Split(s.SecretName, "/")[0]
		s.SecretName = strings.Split(s.SecretName, "/")[1]
	}
	return nil
}

func (s *CloudflareStore) Update(secret *corev1.Secret) error {
	l := log.WithFields(log.Fields{
		"action":          "Update",
		"store":           "cloudflare",
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
	client, err := cloudflare.New(s.ApiKey, s.ApiEmail)
	if err != nil {
		l.WithError(err).Errorf("cloudflare.New error")
		return err
	}
	certRequest := cloudflare.ZoneCustomSSLOptions{
		Certificate: string(c.Certificate),
		PrivateKey:  string(c.Key),
	}
	origCertId := s.CertId
	var sslCert cloudflare.ZoneCustomSSL
	if s.CertId != "" {
		sslCert, err = client.UpdateSSL(context.Background(), s.ZoneId, s.CertId, certRequest)
		if err != nil {
			l.WithError(err).Errorf("cloudflare.UpdateZoneCustomSSL error")
			return err
		}
	} else {
		sslCert, err = client.CreateSSL(context.Background(), s.ZoneId, certRequest)
		if err != nil {
			l.WithError(err).Errorf("cloudflare.CreateZoneCustomSSL error")
			return err
		}
	}
	s.CertId = sslCert.ID
	l.WithField("id", sslCert.ID).Debugf("certificate synced")
	if origCertId != s.CertId {
		secret.ObjectMeta.Annotations[state.OperatorName+"/cloudflare-cert-id"] = s.CertId
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
