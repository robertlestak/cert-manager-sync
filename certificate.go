package main

import (
	corev1 "k8s.io/api/core/v1"
	"strings"
)

// k8sTLSSecretToTextCert converts a k8s secret to a properly-formatted TLS Certificate
func k8sTLSSecretToTextCert(s corev1.Secret) *Certificate {
	c := separateCerts(s.ObjectMeta.Name, s.Data["ca.crt"], s.Data["tls.crt"], s.Data["tls.key"])
	c.Annotations = s.Annotations
	c.Labels = s.Labels
	return c
}

// separateCerts ensures that certificates are configured appropriately
func separateCerts(name string, ca, crt, key []byte) *Certificate {
	b := "-----BEGIN CERTIFICATE-----\n"
	str := strings.Split(string(crt), b)
	nc := b + str[1]
	ch := strings.Join(str[:len(str)-1], b)
	cert := &Certificate{
		SecretName:  name,
		Chain:       []byte(ch),
		Certificate: []byte(nc),
		Key:         key,
	}
	return cert
}

// SortK8sSecretsForAWSProcessing accepts a slice of K8s Secrets and returns only those configured
// for replication to ACM/ASM
func SortK8sSecretsForAWSProcessing(s []corev1.Secret) []corev1.Secret {
	var ac []corev1.Secret
	for _, v := range s {
		acmEnabled := v.Annotations[operatorName+"/acm-enabled"]
		asmEnabled := v.Annotations[operatorName+"/asm-enabled"]
		if (acmEnabled == "true" || asmEnabled == "true") && cacheChanged(v) {
			ac = append(ac, v)
		}
	}
	return ac
}
