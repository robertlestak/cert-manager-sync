package hetznercloud

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type HetznerStore struct {
	SecretName      string
	SecretNamespace string
	ApiToken        string
	CertName        string
	CertId          int64
	Labels          map[string]string
}

func (s *HetznerStore) GetApiToken(ctx context.Context) error {
	gopt := metav1.GetOptions{}
	sc, err := state.KubeClient.CoreV1().Secrets(s.SecretNamespace).Get(ctx, s.SecretName, gopt)
	if err != nil {
		return err
	}
	if sc.Data["api_token"] == nil && sc.Data["token"] == nil {
		return fmt.Errorf("api_token or token not found in secret %s/%s", s.SecretNamespace, s.SecretName)
	}
	// Support both "api_token" and "token" for compatibility
	if sc.Data["api_token"] != nil {
		s.ApiToken = string(sc.Data["api_token"])
	} else {
		s.ApiToken = string(sc.Data["token"])
	}
	return nil
}

func (s *HetznerStore) FromConfig(c tlssecret.GenericSecretSyncConfig) error {
	l := log.WithFields(log.Fields{
		"action": "FromConfig",
		"store":  "hetznercloud",
	})
	l.Debugf("FromConfig")
	
	if c.Config["secret-name"] != "" {
		s.SecretName = c.Config["secret-name"]
	}
	if c.Config["cert-name"] != "" {
		s.CertName = c.Config["cert-name"]
	}
	if c.Config["cert-id"] != "" {
		certId, err := strconv.ParseInt(c.Config["cert-id"], 10, 64)
		if err != nil {
			l.WithError(err).Errorf("failed to parse cert-id")
			return err
		}
		s.CertId = certId
	}
	
	// Parse labels if provided
	s.Labels = make(map[string]string)
	for k, v := range c.Config {
		if strings.HasPrefix(k, "label-") {
			labelKey := strings.TrimPrefix(k, "label-")
			s.Labels[labelKey] = v
		}
	}
	
	// if secret name is in the format of "namespace/secretname" then parse it
	if strings.Contains(s.SecretName, "/") {
		s.SecretNamespace = strings.Split(s.SecretName, "/")[0]
		s.SecretName = strings.Split(s.SecretName, "/")[1]
	}
	
	return nil
}

func (s *HetznerStore) Sync(c *tlssecret.Certificate) (map[string]string, error) {
	s.SecretNamespace = c.Namespace
	l := log.WithFields(log.Fields{
		"action":          "Update",
		"store":           "hetznercloud",
		"certName":        s.CertName,
		"secretName":      s.SecretName,
		"secretNamespace": s.SecretNamespace,
	})
	l.Debugf("Update")
	
	if s.SecretName == "" && s.ApiToken == "" {
		return nil, fmt.Errorf("secret name not found in certificate annotations")
	}
	
	ctx := context.Background()
	// Only get API token from K8s secret if not already set (e.g., for testing)
	if s.ApiToken == "" {
		if err := s.GetApiToken(ctx); err != nil {
			l.WithError(err).Errorf("GetApiToken error")
			return nil, err
		}
	}
	
	// Create Hetzner Cloud client
	client := hcloud.NewClient(hcloud.WithToken(s.ApiToken))
	
	// Prepare certificate name - use provided name or use secret name
	certName := s.CertName
	if certName == "" {
		certName = c.SecretName
	}
	
	// Check if we need to update an existing certificate
	origCertId := s.CertId
	
	// If we have a cert ID, try to delete the old certificate first
	// Hetzner Cloud doesn't support in-place updates, so we need to delete and recreate
	if s.CertId != 0 {
		l.WithField("id", s.CertId).Debugf("checking existing certificate")
		
		// Check if certificate exists
		existingCert, _, err := client.Certificate.GetByID(ctx, s.CertId)
		if err != nil {
			l.WithError(err).Warnf("failed to get existing certificate, it may have been deleted")
		} else if existingCert != nil {
			// Check if certificate is in use
			if len(existingCert.UsedBy) > 0 {
				l.Warnf("certificate %d is in use by %d resources, skipping deletion", s.CertId, len(existingCert.UsedBy))
				// Generate a new name for the certificate to avoid conflicts
				certName = fmt.Sprintf("%s-%d", certName, origCertId)
			} else {
				// Delete the old certificate
				l.WithField("id", s.CertId).Debugf("deleting old certificate")
				_, err = client.Certificate.Delete(ctx, existingCert)
				if err != nil {
					l.WithError(err).Errorf("failed to delete old certificate")
					// Continue anyway - we'll try to create a new one
				} else {
					l.WithField("id", s.CertId).Debugf("old certificate deleted")
				}
			}
		}
	}
	
	// Create the new certificate
	createOpts := hcloud.CertificateCreateOpts{
		Name:        certName,
		Type:        hcloud.CertificateTypeUploaded,
		Certificate: string(c.Certificate),
		PrivateKey:  string(c.Key),
		Labels:      s.Labels,
	}
	
	l.WithField("name", certName).Debugf("creating new certificate")
	cert, _, err := client.Certificate.Create(ctx, createOpts)
	if err != nil {
		l.WithError(err).Errorf("failed to create certificate")
		return nil, err
	}
	
	l = l.WithField("id", cert.ID)
	s.CertId = cert.ID
	
	// Prepare updates to annotations if cert ID changed
	var newKeys map[string]string
	if origCertId != s.CertId {
		newKeys = map[string]string{
			"cert-id": strconv.FormatInt(s.CertId, 10),
		}
	}
	
	l.Info("certificate synced")
	return newKeys, nil
}