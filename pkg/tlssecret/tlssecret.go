package tlssecret

import corev1 "k8s.io/api/core/v1"

type Certificate struct {
	SecretName  string
	Namespace   string
	Annotations map[string]string
	Labels      map[string]string
	Certificate []byte
	Key         []byte
}

func ParseSecret(s *corev1.Secret) *Certificate {
	c := &Certificate{
		SecretName:  s.ObjectMeta.Name,
		Annotations: s.ObjectMeta.Annotations,
		Labels:      s.ObjectMeta.Labels,
		Certificate: s.Data["tls.crt"],
		Key:         s.Data["tls.key"],
	}
	return c
}
