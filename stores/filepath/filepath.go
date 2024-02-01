package filepath

import (
	"fmt"
	"os"

	fp "path/filepath"

	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
)

type FilepathStore struct {
	Directory string
	CertFile  string
	KeyFile   string
}

func (s *FilepathStore) ParseCertificate(c *tlssecret.Certificate) error {
	l := log.WithFields(log.Fields{
		"action": "ParseCertificate",
	})
	l.Debugf("ParseCertificate")
	if c.Annotations[state.OperatorName+"/filepath-dir"] != "" {
		s.Directory = c.Annotations[state.OperatorName+"/filepath-dir"]
	}
	if c.Annotations[state.OperatorName+"/filepath-cert"] != "" {
		s.CertFile = c.Annotations[state.OperatorName+"/filepath-cert"]
	} else {
		s.CertFile = "tls.crt"
	}
	if c.Annotations[state.OperatorName+"/filepath-key"] != "" {
		s.KeyFile = c.Annotations[state.OperatorName+"/filepath-key"]
	} else {
		s.KeyFile = "tls.key"
	}
	return nil
}

func (s *FilepathStore) Update(secret *corev1.Secret) error {
	l := log.WithFields(log.Fields{
		"action":          "Update",
		"store":           "heroku",
		"secretName":      secret.ObjectMeta.Name,
		"secretNamespace": secret.ObjectMeta.Namespace,
	})
	l.Debugf("Update")
	c := tlssecret.ParseSecret(secret)
	if err := s.ParseCertificate(c); err != nil {
		l.WithError(err).Errorf("ParseCertificate error")
		return err
	}
	if s.Directory == "" {
		return fmt.Errorf("filepath-dir annotation is required")
	}
	if s.CertFile == "" {
		s.CertFile = "tls.crt"
	}
	if s.KeyFile == "" {
		s.KeyFile = "tls.key"
	}
	certPath := fp.Join(s.Directory, s.CertFile)
	keyPath := fp.Join(s.Directory, s.KeyFile)
	if err := os.WriteFile(certPath, c.Certificate, 0644); err != nil {
		l.WithError(err).Errorf("WriteFile error")
		return err
	}
	if err := os.WriteFile(keyPath, c.Key, 0644); err != nil {
		l.WithError(err).Errorf("WriteFile error")
		return err
	}
	l.Info("certificate synced")
	return nil
}
