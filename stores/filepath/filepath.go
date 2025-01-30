package filepath

import (
	"fmt"
	"os"

	fp "path/filepath"

	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	log "github.com/sirupsen/logrus"
)

type FilepathStore struct {
	Directory string
	CAFile    string
	CertFile  string
	KeyFile   string
}

func (s *FilepathStore) FromConfig(c tlssecret.GenericSecretSyncConfig) error {
	l := log.WithFields(log.Fields{
		"action": "FromConfig",
	})
	l.Debugf("FromConfig")
	if c.Config["dir"] != "" {
		s.Directory = c.Config["dir"]
	}
	if c.Config["cert"] != "" {
		s.CertFile = c.Config["cert"]
	} else {
		s.CertFile = "tls.crt"
	}
	if c.Config["key"] != "" {
		s.KeyFile = c.Config["key"]
	} else {
		s.KeyFile = "tls.key"
	}
	if c.Config["ca"] != "" {
		s.CAFile = c.Config["ca"]
	} else {
		s.CAFile = "ca.crt"
	}
	return nil
}

func (s *FilepathStore) Sync(c *tlssecret.Certificate) (map[string]string, error) {
	l := log.WithFields(log.Fields{
		"action":          "Sync",
		"store":           "filepath",
		"secretName":      c.SecretName,
		"secretNamespace": c.Namespace,
	})
	l.Debugf("Update")
	if s.Directory == "" {
		return nil, fmt.Errorf("filepath-dir annotation is required")
	}
	if s.CertFile == "" {
		s.CertFile = "tls.crt"
	}
	if s.KeyFile == "" {
		s.KeyFile = "tls.key"
	}
	if s.CAFile == "" {
		s.CAFile = "ca.crt"
	}
	certPath := fp.Join(s.Directory, s.CertFile)
	keyPath := fp.Join(s.Directory, s.KeyFile)
	caPath := fp.Join(s.Directory, s.CAFile)
	l = l.WithFields(log.Fields{
		"id": certPath,
	})
	if err := os.WriteFile(certPath, c.Certificate, 0644); err != nil {
		l.WithError(err).Errorf("sync error")
		return nil, err
	}
	if err := os.WriteFile(keyPath, c.Key, 0644); err != nil {
		l.WithError(err).Errorf("sync error")
		return nil, err
	}
	if len(c.Ca) > 0 {
		if err := os.WriteFile(caPath, c.Ca, 0644); err != nil {
			l.WithError(err).Errorf("sync error")
			return nil, err
		}
	}
	l.Info("certificate synced")
	return nil, nil
}
