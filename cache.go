package main

import (
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"os"
)

func addToCache(c *Certificate) {
	var nc []*Certificate
	for _, v := range cache {
		if v.SecretName != c.SecretName {
			nc = append(nc, v)
		}
	}
	nc = append(nc, c)
	cache = nc
}

func cacheChanged(s corev1.Secret) bool {
	var found bool

	l := log.WithFields(
		log.Fields{
			"action":     "cacheChanged",
			"secretName": s.ObjectMeta.Name,
		},
	)

	l.Print("check cacheChanged")
	if os.Getenv("CACHE_DISABLE") == "true" {
		l.Print("cache disabled")
		return true
	}

	if len(cache) == 0 {
		l.Print("cache is empty")
		return true
	}
	l.Printf("cache length: %d", len(cache))

	for _, cacheItem := range cache {
		l.Debugf("checking cache for secret %s", cacheItem.SecretName)

		nameMatch := cacheItem.SecretName == s.ObjectMeta.Name

		if nameMatch {
			found = true
		}

		tc := k8sTLSSecretToTextCert(s)
		certChanged := string(cacheItem.Certificate) != string(tc.Certificate)
		labelsChanged := stringMapChanged(cacheItem.Labels, tc.Labels)
		annotationsChanged := stringMapChanged(cacheItem.Annotations, tc.Annotations)

		l.Debugf("cache status %s: certChanged=%t labelsChanged=%t annotationsChanged=%t",
			cacheItem.SecretName, certChanged, labelsChanged, annotationsChanged)

		if nameMatch && (certChanged || labelsChanged || annotationsChanged) {
			l.Printf("cache changed: %s", s.ObjectMeta.Name)
			return true
		}
	}

	if !found {
		l.Printf("cache changed: %s", s.ObjectMeta.Name)
		return true
	}

	l.Print("cache not changed")
	return false
}
