package main

import (
	"context"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

var (
	// k8sClient contains the kubernetes API client
	k8sClient    *kubernetes.Clientset
	operatorName string
	cache        []*Certificate
)

// Certificate represents a properly formatted TLS certificate
type Certificate struct {
	SecretName  string
	Annotations map[string]string
	Labels      map[string]string
	Chain       []byte
	Certificate []byte
	Key         []byte
}

// createKubeClient creates a global k8s client
func createKubeClient() error {
	l := log.WithFields(
		log.Fields{
			"action": "createKubeClient",
		},
	)
	l.Print("get createKubeClient")
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
			l.Printf("res.InClusterConfig error=%v", err)
			return err
		}
	} else {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			l.Printf("clientcmd.BuildConfigFromFlags error=%v", err)
			return err
		}
	}
	k8sClient, err = kubernetes.NewForConfig(config)
	if err != nil {
		l.Printf("kubernetes.NewForConfig error=%v", err)
		return err
	}
	return nil
}

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

func cacheChanged(s corev1.Secret) bool {
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
	for _, v := range cache {
		l.Debugf("checking cache for secret %s", v.SecretName)
		tc := secretToCert(s)
		nameMatch := v.SecretName == s.ObjectMeta.Name
		certChanged := string(v.Certificate) != string(tc.Certificate)
		labelsChanged := stringMapChanged(v.Labels, tc.Labels)
		annotationsChanged := stringMapChanged(v.Annotations, tc.Annotations)
		l.Debugf("cache status %s: certChanged=%t labelsChanged=%t annotationsChanged=%t", v.SecretName, certChanged, labelsChanged, annotationsChanged)
		if nameMatch && (certChanged || labelsChanged || annotationsChanged) {
			l.Printf("cache changed: %s", s.ObjectMeta.Name)
			return true
		}
	}
	l.Print("cache not changed")
	return false
}

// getSecrets returns all sync-enabled secrets managed by the cert-manager-sync operator
func getSecrets() ([]corev1.Secret, error) {
	var slo []corev1.Secret
	var err error
	l := log.WithFields(
		log.Fields{
			"action": "getSecrets",
		},
	)
	l.Print("get secrets in namespace", os.Getenv("SECRETS_NAMESPACE"))
	sc := k8sClient.CoreV1().Secrets(os.Getenv("SECRETS_NAMESPACE"))
	lo := &metav1.ListOptions{}
	sl, jerr := sc.List(context.Background(), *lo)
	if jerr != nil {
		l.Printf("list error=%v", jerr)
		return slo, jerr
	}
	l.Printf("range secrets: %d", len(sl.Items))
	for _, s := range sl.Items {
		l.Debugf("secret=%s/%s labels=%v annotations=%v", s.ObjectMeta.Namespace, s.ObjectMeta.Name, s.ObjectMeta.Labels, s.ObjectMeta.Annotations)
		if len(s.Data["tls.crt"]) == 0 || len(s.Data["tls.key"]) == 0 {
			l.Debug("skipping secret without tls.crt or tls.key")
			continue
		}
		if s.Annotations[operatorName+"/sync-enabled"] == "true" {
			l.Printf("cert secret found: %s", s.ObjectMeta.Name)
			slo = append(slo, s)
		}
	}
	l.Debugf("returning %d enabled secrets", len(slo))
	return slo, err
}

// secretToCert converts a k8s secret to a properly-formatted TLS Certificate
func secretToCert(s corev1.Secret) *Certificate {
	c := separateCerts(s.ObjectMeta.Name, s.Data["ca.crt"], s.Data["tls.crt"], s.Data["tls.key"])
	c.Annotations = s.Annotations
	c.Labels = s.Labels
	return c
}

func init() {
	ll, lerr := log.ParseLevel(os.Getenv("LOG_LEVEL"))
	if lerr != nil {
		ll = log.InfoLevel
	}
	log.SetLevel(ll)
	l := log.WithFields(
		log.Fields{
			"action": "init",
		},
	)
	l.Print("init")
	if os.Getenv("OPERATOR_NAME") == "" {
		l.Fatal("OPERATOR_NAME not set")
	} else {
		operatorName = os.Getenv("OPERATOR_NAME")
	}
	cerr := createKubeClient()
	if cerr != nil {
		l.Fatal(cerr)
	}
}

func main() {
	l := log.WithFields(
		log.Fields{
			"action": "main",
		},
	)
	l.Debug("starting")
	// main loop
	for {
		l.Print("main loop")
		l.Debug("main loop getSecrets")
		as, serr := getSecrets()
		if serr != nil {
			l.Fatal(serr)
		}
		l.Debug("main handleACMCerts")
		go handleACMCerts(as)
		l.Debug("main handleIncapsulaCerts")
		go handleIncapsulaCerts(as)
		l.Debug("main handleThreatxCerts")
		go handleThreatxCerts(as)
		l.Printf("sleep main loop")
		l.Debug("main handleVaultCerts")
		go handleVaultCerts(as)
		time.Sleep(time.Second * 60)
	}
}
