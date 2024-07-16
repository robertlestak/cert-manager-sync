package state

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

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
)

func addHashAnnotation(secretNamespace, secretName, hash string) error {
	l := log.WithFields(log.Fields{
		"action": "incrementRetries",
		"secret": fmt.Sprintf("%s/%s", secretNamespace, secretName),
		"hash":   hash,
	})
	l.Debugf("incrementRetries %s/%s", secretNamespace, secretName)
	// get the secret from k8s, since we don't know if data has been changed by a store
	if KubeClient == nil {
		l.Debugf("KubeClient is nil")
		return fmt.Errorf("KubeClient is nil")
	}
	gopt := metav1.GetOptions{}
	secret, err := KubeClient.CoreV1().Secrets(secretNamespace).Get(context.Background(), secretName, gopt)
	if err != nil {
		l.WithError(err).Errorf("Get error")
		return err
	}
	if secret.Annotations == nil {
		secret.Annotations = make(map[string]string)
	}
	secret.Annotations[OperatorName+"/hash"] = hash
	uo := metav1.UpdateOptions{
		FieldManager: OperatorName,
	}
	_, err = KubeClient.CoreV1().Secrets(secretNamespace).Update(context.Background(), secret, uo)
	if err != nil {
		l.WithError(err).Errorf("Update secret error")
		return err
	}
	l.Debugf("incremented retries")
	return nil
}

// kvPair represents a key-value pair.
type kvPair struct {
	Key   string
	Value any
}

// hashMapValues takes a map[string]any and returns a deterministic hash of its values.
func hashMapValues(m map[string]any) (string, error) {
	// Convert map to a slice of key-value pairs.
	var pairs []kvPair
	for k, v := range m {
		pairs = append(pairs, kvPair{Key: k, Value: v})
	}

	// Sort the slice by key.
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].Key < pairs[j].Key
	})

	// Serialize the sorted key-value pairs.
	serialized, err := json.Marshal(pairs)
	if err != nil {
		return "", err // Handle serialization error.
	}

	// Hash the serialized string.
	hash := sha256.Sum256(serialized)

	// Return the hash as a hexadecimal string.
	return hex.EncodeToString(hash[:]), nil
}

func hashSecret(s *corev1.Secret) string {
	l := log.WithFields(log.Fields{
		"action": "hashSecret",
	})
	l.Debug("hashing secret")
	var secretHash string
	dataMap := make(map[string]any)
	jd, err := json.Marshal(s.Data)
	if err != nil {
		l.WithError(err).Errorf("json.Marshal error")
		return ""
	}
	if err := json.Unmarshal(jd, &dataMap); err != nil {
		l.WithError(err).Errorf("json.Unmarshal error")
		return ""
	}
	hashedData, err := hashMapValues(dataMap)
	if err != nil {
		l.WithError(err).Errorf("hashMapValues error")
		return ""
	}
	// do the same for operator annotations
	annotationsMap := make(map[string]any)
	for k, v := range s.Annotations {
		// we only care about annotations that start with the operator name
		// and we do not want to hash the hash annotation itself
		if strings.HasPrefix(k, OperatorName) && k != OperatorName+"/hash" {
			annotationsMap[k] = v
		}
	}
	jd, err = json.Marshal(annotationsMap)
	if err != nil {
		l.WithError(err).Errorf("json.Marshal error")
		return ""
	}
	if err := json.Unmarshal(jd, &annotationsMap); err != nil {
		l.WithError(err).Errorf("json.Unmarshal error")
		return ""
	}
	hashedAnnotations, err := hashMapValues(annotationsMap)
	if err != nil {
		l.WithError(err).Errorf("hashMapValues error")
		return ""
	}
	// combine the two hashes
	secretHash = hashedData + hashedAnnotations
	// hash the combined hash
	hash := sha256.Sum256([]byte(secretHash))
	secretHash = hex.EncodeToString(hash[:])
	return secretHash
}

func cmsHash(s *corev1.Secret) string {
	l := log.WithFields(log.Fields{
		"action":    "cmsHash",
		"namespace": s.Namespace,
		"name":      s.Name,
	})
	l.Debug("cmsHash")
	var cmsHash string
	if s.Annotations[OperatorName+"/hash"] != "" {
		cmsHash = s.Annotations[OperatorName+"/hash"]
	}
	return cmsHash
}

func cacheSecret(s *corev1.Secret) error {
	l := log.WithFields(
		log.Fields{
			"action": "cacheSecret",
		},
	)
	l.Debug("caching secret")
	sHash := hashSecret(s)
	if err := addHashAnnotation(s.Namespace, s.Name, sHash); err != nil {
		l.WithError(err).Errorf("addHashAnnotation error")
		return err
	}
	return nil
}

func Cache(s *corev1.Secret) error {
	l := log.WithFields(
		log.Fields{
			"action":     "Cache",
			"secretName": s.ObjectMeta.Name,
			"namespace":  s.ObjectMeta.Namespace,
		},
	)
	l.Debug("caching secret")
	return cacheSecret(s)
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
	secretHash := hashSecret(s)
	existingHash := cmsHash(s)
	l = l.WithFields(log.Fields{
		"secretHash":   secretHash,
		"existingHash": existingHash,
	})
	l.Debugf("secretHash=%s existingHash=%s", secretHash, existingHash)
	if secretHash != existingHash {
		l.Debugf("cache changed")
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
	l.Trace("checking if secret is watched")
	if s.Annotations[OperatorName+"/sync-enabled"] != "true" {
		l.Trace("sync-enabled not true")
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
