package tlssecret

import corev1 "k8s.io/api/core/v1"

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
