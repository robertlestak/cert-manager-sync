package tlssecret

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
)

type Certificate struct {
	SecretName  string
	Namespace   string
	Syncs       []*GenericSecretSyncConfig
	Ca          []byte
	Certificate []byte
	Key         []byte
}

func ParseSecret(s *corev1.Secret) *Certificate {
	syncs, err := SyncsForSecret(s)
	if err != nil {
		return nil
	}
	c := &Certificate{
		SecretName:  s.ObjectMeta.Name,
		Namespace:   s.ObjectMeta.Namespace,
		Syncs:       syncs,
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

func GetValue(s *corev1.Secret, k string) ([]byte, error) {
	v, ok := s.Data[k]
	if !ok {
		return nil, fmt.Errorf("%s not found in secret %s/%s", k, s.GetNamespace(), s.GetName())
	}
	return v, nil
}
