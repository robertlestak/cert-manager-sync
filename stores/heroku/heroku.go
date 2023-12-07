package heroku

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	heroku "github.com/heroku/heroku-go/v5"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type HerokuStore struct {
	SecretName      string
	SecretNamespace string
	ApiKey          string
	AppName         string
	CertName        string
}

func (s *HerokuStore) GetApiKey(ctx context.Context) error {
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

func (s *HerokuStore) ParseCertificate(c *tlssecret.Certificate) error {
	l := log.WithFields(log.Fields{
		"action": "ParseCertificate",
	})
	l.Debugf("ParseCertificate")
	if c.Annotations[state.OperatorName+"/heroku-secret-name"] != "" {
		s.SecretName = c.Annotations[state.OperatorName+"/heroku-secret-name"]
	}
	if c.Annotations[state.OperatorName+"/heroku-app"] != "" {
		s.AppName = c.Annotations[state.OperatorName+"/heroku-app"]
	}
	if c.Annotations[state.OperatorName+"/heroku-cert-name"] != "" {
		s.CertName = c.Annotations[state.OperatorName+"/heroku-cert-name"]
	}
	// if secret name is in the format of "namespace/secretname" then parse it
	if strings.Contains(s.SecretName, "/") {
		s.SecretNamespace = strings.Split(s.SecretName, "/")[0]
		s.SecretName = strings.Split(s.SecretName, "/")[1]
	}
	return nil
}

func (s *HerokuStore) Update(secret *corev1.Secret) error {
	l := log.WithFields(log.Fields{
		"action":          "Update",
		"store":           "heroku",
		"appName":         s.AppName,
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
	client := heroku.NewService(&http.Client{
		Transport: &heroku.Transport{
			BearerToken: s.ApiKey,
		},
	})
	origCertName := s.CertName
	if s.CertName == "" {
		sniOpts := heroku.SniEndpointCreateOpts{
			CertificateChain: string(c.Certificate),
			PrivateKey:       string(c.Key),
		}
		ep, err := client.SniEndpointCreate(ctx, s.AppName, sniOpts)
		if err != nil {
			l.WithError(err).Errorf("heroku.SniEndpointCreate error")
			return err
		}
		l.Debugf("heroku.SniEndpointCreate success: %s", ep.Name)
		s.CertName = ep.Name
	} else {
		sniOpts := heroku.SniEndpointUpdateOpts{
			CertificateChain: string(c.Certificate),
			PrivateKey:       string(c.Key),
		}
		ep, err := client.SniEndpointUpdate(ctx, s.AppName, s.CertName, sniOpts)
		if err != nil {
			l.WithError(err).Errorf("heroku.SniEndpointUpdate error")
			return err
		}
		l.Debugf("heroku.SniEndpointUpdate success: %s", ep.Name)
		s.CertName = ep.Name
	}
	if origCertName != s.CertName {
		secret.ObjectMeta.Annotations[state.OperatorName+"/heroku-cert-name"] = s.CertName
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
