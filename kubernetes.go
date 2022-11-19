package main

import (
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"os"
	"path/filepath"
)

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

// getK8sSecrets returns all sync-enabled secrets managed by the cert-manager-sync operator
func getK8sSecrets() ([]corev1.Secret, error) {
	var slo []corev1.Secret
	var err error
	l := log.WithFields(
		log.Fields{
			"action": "getK8sSecrets",
		},
	)
	l.Print("get secrets from namespace", os.Getenv("SECRETS_NAMESPACE"))
	sc := k8sClient.CoreV1().Secrets(os.Getenv("SECRETS_NAMESPACE"))
	lo := &metav1.ListOptions{}
	sl, _err := sc.List(context.Background(), *lo)
	if _err != nil {
		l.Printf("list error=%v", _err)
		return slo, _err
	}

	l.Printf("range count of secrets: %d", len(sl.Items))
	for _, s := range sl.Items {
		l.Debugf("secret=%s/%s labels=%v annotations=%v",
			s.ObjectMeta.Namespace, s.ObjectMeta.Name, s.ObjectMeta.Labels, s.ObjectMeta.Annotations)

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
