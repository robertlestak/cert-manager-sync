package heroku

import (
	"context"
	"errors"
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
		return nil, fmt.Errorf("failed to get Heroku API key from secret %s/%s: %w", s.SecretNamespace, s.SecretName, err)
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
			return nil, fmt.Errorf("failed to create Heroku SNI endpoint for app %s: %w", s.AppName, err)
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
			return nil, fmt.Errorf("failed to update Heroku SNI endpoint %s for app %s: %w", s.CertName, s.AppName, err)
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

// isHerokuNotFound returns true when the Heroku API responded 404.
func isHerokuNotFound(err error) bool {
	if err == nil {
		return false
	}
	var he heroku.Error
	if errors.As(err, &he) {
		return he.StatusCode == 404
	}
	return false
}

// Delete removes the SNI endpoint from the Heroku app. 404 responses are
// treated as success so the operation is idempotent.
func (s *HerokuStore) Delete(ctx context.Context) error {
	l := log.WithFields(log.Fields{
		"action":   "heroku.Delete",
		"app":      s.AppName,
		"certName": s.CertName,
	})
	if s.CertName == "" {
		// Sync never populated cert-name (the SNI endpoint identifier), so
		// there is no remote endpoint to clean up. Treat as success so
		// opt-in secrets that failed their initial sync are not wedged on
		// deletion.
		l.Debug("no heroku cert-name recorded; nothing to delete")
		return nil
	}
	if s.AppName == "" {
		return fmt.Errorf("heroku app not set; cannot delete %s", s.CertName)
	}
	if s.SecretName == "" {
		return fmt.Errorf("heroku secret-name not set; cannot resolve API key for delete")
	}
	if err := s.GetApiKey(ctx); err != nil {
		return fmt.Errorf("heroku credentials lookup failed: %w", err)
	}
	client := heroku.NewService(&http.Client{
		Transport: &heroku.Transport{
			BearerToken: s.ApiKey,
		},
	})
	if _, err := client.SniEndpointDelete(ctx, s.AppName, s.CertName); err != nil {
		if isHerokuNotFound(err) {
			l.Debug("heroku SNI endpoint already absent; treating delete as success")
			return nil
		}
		return fmt.Errorf("delete Heroku SNI endpoint %s on app %s: %w", s.CertName, s.AppName, err)
	}
	l.Info("certificate deleted from heroku")
	return nil
}
