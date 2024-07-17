package tlssecret

import (
	"encoding/base64"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
)

type Certificate struct {
	SecretName  string
	Namespace   string
	Annotations map[string]string
	Labels      map[string]string
	Ca          []byte
	Certificate []byte
	Key         []byte
}

func ParseSecret(s *corev1.Secret) *Certificate {
	c := &Certificate{
		SecretName:  s.ObjectMeta.Name,
		Namespace:   s.ObjectMeta.Namespace,
		Annotations: s.ObjectMeta.Annotations,
		Labels:      s.ObjectMeta.Labels,
		Ca:          s.Data["ca.crt"],
		Certificate: s.Data["tls.crt"],
		Key:         s.Data["tls.key"],
	}
	return c
}

// FullChain returns the full certificate chain, including the CA certificate if present
func (c *Certificate) FullChain() []byte {
	if len(c.Ca) > 0 {
		return append(append(c.Certificate, '\n'), c.Ca...)
	}
	return c.Certificate
}

func (c *Certificate) Base64Decode() error {
	l := log.WithFields(log.Fields{
		"action": "Base64Decode",
	})
	var err error
	if c.Ca != nil {
		c.Ca, err = base64.StdEncoding.DecodeString(string(c.Ca))
		if err != nil {
			l.WithError(err).Errorf("error decoding ca")
			return err
		}
	}
	if c.Certificate != nil {
		c.Certificate, err = base64.StdEncoding.DecodeString(string(c.Certificate))
		if err != nil {
			l.WithError(err).Errorf("error decoding certificate")
			return err
		}
	}
	if c.Key != nil {
		c.Key, err = base64.StdEncoding.DecodeString(string(c.Key))
		if err != nil {
			l.WithError(err).Errorf("error decoding key")
			return err
		}
	}
	return nil
}
