package state

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

var (
	OperatorName = "cert-manager-sync.lestak.sh"
	KubeClient   *kubernetes.Clientset
	Cache        map[string]*corev1.Secret
	cacheLock    sync.Mutex
)

func AddToCache(secret *corev1.Secret) {
	l := log.WithFields(
		log.Fields{
			"action":     "addToCache",
			"secretName": secret.ObjectMeta.Name,
			"namespace":  secret.ObjectMeta.Namespace,
		},
	)
	l.Debug("adding secret to cache")
	cacheLock.Lock()
	defer cacheLock.Unlock()
	key := fmt.Sprintf("%s/%s", secret.Namespace, secret.Name)
	if Cache == nil {
		Cache = make(map[string]*corev1.Secret)
	}
	Cache[key] = secret
	l.Debugf("cache length: %d", len(Cache))
}

func stringMapChanged(a, b map[string]string) bool {
	l := log.WithFields(log.Fields{
		"action": "stringMapChanged",
	})
	l.Debug("Checking stringMapChanged")
	if len(a) != len(b) {
		l.Debugf("stringMapChanged: len(a)=%d len(b)=%d", len(a), len(b))
		return true
	}
	for k, v := range a {
		if b[k] != v {
			l.Debugf("stringMapChanged: a[%s]=%s b[%s]=%s", k, v, k, b[k])
			return true
		}
	}
	l.Debug("stringMapChanged: false")
	return false
}

func CacheChanged(s *corev1.Secret) bool {
	l := log.WithFields(
		log.Fields{
			"action":     "cacheChanged",
			"secretName": s.ObjectMeta.Name,
		},
	)
	l.Debug("checking cacheChanged")
	if os.Getenv("CACHE_DISABLE") == "true" {
		l.Debug("cache disabled")
		return true
	}
	key := fmt.Sprintf("%s/%s", s.Namespace, s.Name)
	if Cache == nil {
		l.Debug("cache not initialized")
		return true
	}
	if _, exists := Cache[key]; !exists {
		// Secret not found in the cache, consider it as changed
		l.Debug("secret not found in cache")
		return true
	}
	oldSecret := Cache[key]
	oldCert := tlssecret.ParseSecret(oldSecret)
	newCert := tlssecret.ParseSecret(s)

	certChanged := string(oldCert.Certificate) != string(newCert.Certificate)
	labelsChanged := stringMapChanged(oldSecret.Labels, s.Labels)
	annotationsChanged := stringMapChanged(oldSecret.Annotations, s.Annotations)

	l.Debugf("cache status %s: certChanged=%t labelsChanged=%t annotationsChanged=%t",
		oldSecret.Name, certChanged, labelsChanged, annotationsChanged)

	if certChanged || labelsChanged || annotationsChanged {
		l.Debugf("cache changed: %s", s.ObjectMeta.Name)
		return true
	}
	l.Debugf("cache not changed")
	return false
}

func CreateKubeClient() error {
	l := log.WithFields(
		log.Fields{
			"action": "createKubeClient",
		},
	)
	l.Debug("get createKubeClient")
	var kubeconfig string
	var err error
	if os.Getenv("KUBECONFIG") != "" {
		kubeconfig = os.Getenv("KUBECONFIG")
	} else if home := homedir.HomeDir(); home != "" {
		kubeconfig = filepath.Join(home, ".kube", "config")
	}
	var config *rest.Config
	// naïvely assume if no kubeconfig file that we are running in cluster
	if _, err := os.Stat(kubeconfig); os.IsNotExist(err) {
		config, err = rest.InClusterConfig()
		if err != nil {
			l.Debugf("res.InClusterConfig error=%v", err)
			return err
		}
	} else {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			l.Debugf("clientcmd.BuildConfigFromFlags error=%v", err)
			return err
		}
	}
	KubeClient, err = kubernetes.NewForConfig(config)
	if err != nil {
		l.Debugf("kubernetes.NewForConfig error=%v", err)
		return err
	}
	return nil
}

func namespaceDisabled(n string) bool {
	// if DISABLED_NAMESPACES is set, don't watch those namespaces
	disabledNs := strings.Split(os.Getenv("DISABLED_NAMESPACES"), ",")
	for _, ns := range disabledNs {
		if ns == n {
			return true
		}
	}
	// if DISABLED_NAMESPACES is not set, watch all namespaces
	return false
}

func namespaceEnabled(n string) bool {
	// SECRETS_NAMESPACE is deprecated and has been replaced by ENABLED_NAMESPACES.
	// SECRETS_NAMESPACE will be removed in a future release
	// if a single SECRETS_NAMESPACE is set, only watch that namespace
	if os.Getenv("SECRETS_NAMESPACE") != "" && n != os.Getenv("SECRETS_NAMESPACE") {
		return false
	} else if os.Getenv("SECRETS_NAMESPACE") != "" && n == os.Getenv("SECRETS_NAMESPACE") {
		return true
	}
	// if ENABLED_NAMESPACES is set, only watch those namespaces
	if os.Getenv("ENABLED_NAMESPACES") != "" {
		enabledNs := strings.Split(os.Getenv("ENABLED_NAMESPACES"), ",")
		for _, ns := range enabledNs {
			if ns == n {
				return true
			}
		}
		// if ENABLED_NAMESPACES is set, but the namespace is not in the list, don't watch
		return false
	}
	// if ENABLED_NAMESPACES is not set, watch all namespaces
	return true
}

func SecretWatched(s *corev1.Secret) bool {
	l := log.WithFields(
		log.Fields{
			"action":    "secretWatched",
			"secret":    s.ObjectMeta.Name,
			"namespace": s.ObjectMeta.Namespace,
		})
	if s.Annotations[OperatorName+"/sync-enabled"] != "true" {
		return false
	}
	if namespaceDisabled(s.Namespace) {
		l.Debug("namespace disabled")
		return false
	}
	if !namespaceEnabled(s.Namespace) {
		l.Debug("namespace not enabled")
		return false
	}
	if len(s.Data["tls.crt"]) == 0 || len(s.Data["tls.key"]) == 0 {
		l.Debug("skipping secret without tls.crt or tls.key")
		return false
	}
	l.Debug("returning true")
	return true
}
