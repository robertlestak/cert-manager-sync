package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
	clientconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
)

var (
	OperatorName       = "cert-manager-sync.lestak.sh"
	KubeClient         *kubernetes.Clientset
	EventRecorder      record.EventRecorder
	disabledNamespaces []string
	enabledNamespaces  []string
	cacheDisabled      bool
)

func init() {
	pflag.StringSliceVar(&disabledNamespaces, "disabled.namespaces", nil, "disabled namespaces")
	pflag.StringSliceVar(&enabledNamespaces, "enabled.namespaces", nil, "namespaces to be watched, an empty value indicates all namespaces")
	pflag.BoolVar(&cacheDisabled, "cache.disabled", false, "disable internal cache")
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

func HashSecret(s *corev1.Secret) string {
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
		// also remove the failed-sync-attempts and next-retry annotations
		if k == OperatorName+"/failed-sync-attempts" || k == OperatorName+"/next-retry" {
			delete(annotationsMap, k)
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

func CacheChanged(s *corev1.Secret) bool {
	l := log.WithFields(
		log.Fields{
			"action":     "cacheChanged",
			"secretName": s.ObjectMeta.Name,
		},
	)

	if cacheDisabled {
		return true
	}
	secretHash := HashSecret(s)
	existingHash := cmsHash(s)
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

	config, err := clientconfig.GetConfig()
	if err != nil {
		return err
	}
	KubeClient, err = kubernetes.NewForConfig(config)
	if err != nil {
		l.Debugf("kubernetes.NewForConfig error=%v", err)
		return err
	}
	// Create broadcaster
	broadcaster := record.NewBroadcaster()
	broadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: KubeClient.CoreV1().Events("")})

	// Create event recorder
	EventRecorder = broadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: OperatorName})
	return nil
}

func namespaceDisabled(n string) bool {
	// if disabledNamespaces is set, don't watch those namespaces
	for _, ns := range disabledNamespaces {
		if ns == n {
			return true
		}
	}
	return false
}

func namespaceEnabled(n string) bool {
	// SECRETS_NAMESPACE is deprecated and has been replaced by ENABLED_NAMESPACES.
	// SECRETS_NAMESPACE will be removed in a future release
	// if a single SECRETS_NAMESPACE is set, only watch that namespace
	if v, ok := os.LookupEnv("SECRETS_NAMESPACE"); ok {
		return n == v
	}

	if len(enabledNamespaces) == 0 {
		return true
	}

	// if enabledNamespaces is set, only watch those namespaces
	for _, ns := range enabledNamespaces {
		if ns == n {
			return true
		}
	}
	return false
}

func SecretWatched(s *corev1.Secret) bool {
	l := log.WithFields(
		log.Fields{
			"action":    "secretWatched",
			"secret":    s.ObjectMeta.Name,
			"namespace": s.ObjectMeta.Namespace,
		})
	l.Trace("checking if secret is watched")
	if s.Annotations[OperatorName+"/sync-enabled"] != "true" && s.Annotations[OperatorName+"/enabled"] != "true" {
		l.Trace("enabled not true")
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
