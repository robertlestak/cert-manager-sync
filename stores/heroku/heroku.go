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

func (s *HerokuStore) FromConfig(c tlssecret.GenericSecretSyncConfig) error {
	l := log.WithFields(log.Fields{
		"action": "FromConfig",
	})
	l.Debugf("FromConfig")
	if c.Config["secret-name"] != "" {
		s.SecretName = c.Config["secret-name"]
	}
	if c.Config["app"] != "" {
		s.AppName = c.Config["app"]
	}
	if c.Config["cert-name"] != "" {
		s.CertName = c.Config["cert-name"]
	}
	// if secret name is in the format of "namespace/secretname" then parse it
	if strings.Contains(s.SecretName, "/") {
		s.SecretNamespace = strings.Split(s.SecretName, "/")[0]
		s.SecretName = strings.Split(s.SecretName, "/")[1]
	}
	return nil
}

func (s *HerokuStore) Sync(c *tlssecret.Certificate) (map[string]string, error) {
	s.SecretNamespace = c.Namespace
	l := log.WithFields(log.Fields{
		"action":          "Sync",
		"store":           "heroku",
		"appName":         s.AppName,
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
	client := heroku.NewService(&http.Client{
		Transport: &heroku.Transport{
			BearerToken: s.ApiKey,
		},
	})
	origCertName := s.CertName
	if s.CertName == "" {
		sniOpts := heroku.SniEndpointCreateOpts{
			CertificateChain: string(c.FullChain()),
			PrivateKey:       string(c.Key),
		}
		ep, err := client.SniEndpointCreate(ctx, s.AppName, sniOpts)
		if err != nil {
			l.WithError(err).Errorf("heroku.SniEndpointCreate error")
			return nil, err
		}
		l.Debugf("heroku.SniEndpointCreate success: %s", ep.Name)
		s.CertName = ep.Name
	} else {
		sniOpts := heroku.SniEndpointUpdateOpts{
			CertificateChain: string(c.FullChain()),
			PrivateKey:       string(c.Key),
		}
		ep, err := client.SniEndpointUpdate(ctx, s.AppName, s.CertName, sniOpts)
		if err != nil {
			l.WithError(err).Errorf("heroku.SniEndpointUpdate error")
			return nil, err
		}
		l.Debugf("heroku.SniEndpointUpdate success: %s", ep.Name)
		s.CertName = ep.Name
	}
	l = l.WithFields(log.Fields{
		"id": s.CertName,
	})
	var keyUpdates map[string]string
	if origCertName != s.CertName {
		keyUpdates = map[string]string{
			"cert-name": s.CertName,
		}
	}
	l.Info("certificate synced")
	return keyUpdates, nil
}
