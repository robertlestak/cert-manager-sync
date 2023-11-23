package state

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

var (
	OperatorName = "cert-manager-sync.lestak.sh"
	KubeClient   *kubernetes.Clientset
	Cache        []*corev1.Secret
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
	l.Debug("addToCache")
	cacheLock.Lock()
	var nc []*corev1.Secret
	for _, v := range Cache {
		newKey := fmt.Sprintf("%s/%s", secret.Namespace, secret.Name)
		oldKey := fmt.Sprintf("%s/%s", v.Namespace, v.Name)
		l.Debugf("newKey=%s oldKey=%s", newKey, oldKey)
		if newKey != oldKey {
			nc = append(nc, v)
		}
	}
	nc = append(nc, secret)
	Cache = nc
	l.Debugf("cache length: %d", len(Cache))
	cacheLock.Unlock()
}

func stringMapChanged(a, b map[string]string) bool {
	if len(a) != len(b) {
		return true
	}
	for k, v := range a {
		if b[k] != v {
			return true
		}
	}
	return false
}

func CacheChanged(s *corev1.Secret) bool {
	l := log.WithFields(
		log.Fields{
			"action":     "cacheChanged",
			"secretName": s.ObjectMeta.Name,
		},
	)
	l.Debug("check cacheChanged")
	if os.Getenv("CACHE_DISABLE") == "true" {
		l.Debug("cache disabled")
		return true
	}
	if len(Cache) == 0 {
		l.Debug("cache is empty")
		return true
	}
	l.Debugf("cache length: %d", len(Cache))
	var found bool
	for _, v := range Cache {
		l.Debugf("checking cache for secret %s", v.Name)
		oldCert := tlssecret.ParseSecret(v)
		newCert := tlssecret.ParseSecret(s)
		nameMatch := v.Name == s.ObjectMeta.Name
		namespaceMatch := v.Namespace == s.ObjectMeta.Namespace
		// if no namespace is specified, match all namespaces
		if v.Namespace == "" {
			namespaceMatch = true
		}
		if nameMatch && namespaceMatch {
			found = true
		}
		certChanged := string(oldCert.Certificate) != string(newCert.Certificate)
		labelsChanged := stringMapChanged(v.Labels, s.Labels)
		annotationsChanged := stringMapChanged(v.Annotations, s.Annotations)
		l.Debugf("cache status %s: certChanged=%t labelsChanged=%t annotationsChanged=%t",
			v.Name, certChanged, labelsChanged, annotationsChanged)
		if nameMatch && (certChanged || labelsChanged || annotationsChanged) {
			l.Debugf("cache changed: %s", s.ObjectMeta.Name)
			return true
		}
	}
	if !found {
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

// GetSecrets returns all sync-enabled secrets managed by the cert-manager-sync operator
func GetSecrets(namespace string) ([]corev1.Secret, error) {
	var slo []corev1.Secret
	var err error
	l := log.WithFields(
		log.Fields{
			"action": "getSecrets",
		},
	)
	l.Debugf("getSecrets")
	sc := KubeClient.CoreV1().Secrets(namespace)
	lo := &metav1.ListOptions{}
	sl, jerr := sc.List(context.Background(), *lo)
	if jerr != nil {
		l.WithError(jerr).Errorf("secret.List error")
		return slo, jerr
	}
	l.Debugf("range secrets: %d", len(sl.Items))
	for _, s := range sl.Items {
		l.Debugf("secret=%s/%s labels=%v annotations=%v", s.ObjectMeta.Namespace, s.ObjectMeta.Name, s.ObjectMeta.Labels, s.ObjectMeta.Annotations)
		if len(s.Data["tls.crt"]) == 0 || len(s.Data["tls.key"]) == 0 {
			l.Debug("skipping secret without tls.crt or tls.key")
			continue
		}
		if s.Annotations[OperatorName+"/sync-enabled"] == "true" {
			l.Debugf("cert secret found: %s", s.ObjectMeta.Name)
			slo = append(slo, s)
		}
	}
	l.Debugf("returning %d enabled secrets", len(slo))
	return slo, err
}
