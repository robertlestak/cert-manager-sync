package certmanagersync

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/robertlestak/cert-manager-sync/internal/metrics"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/stores/acm"
	"github.com/robertlestak/cert-manager-sync/stores/cloudflare"
	"github.com/robertlestak/cert-manager-sync/stores/digitalocean"
	"github.com/robertlestak/cert-manager-sync/stores/filepath"
	"github.com/robertlestak/cert-manager-sync/stores/gcpcm"
	"github.com/robertlestak/cert-manager-sync/stores/heroku"
	"github.com/robertlestak/cert-manager-sync/stores/incapsula"
	"github.com/robertlestak/cert-manager-sync/stores/threatx"
	"github.com/robertlestak/cert-manager-sync/stores/vault"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	ErrInvalidStoreType = errors.New("invalid store type")
)

type StoreType string

const (
	ACMStoreType          StoreType = "acm"
	CloudflareStoreType   StoreType = "cloudflare"
	DigitalOceanStoreType StoreType = "digitalocean"
	FilepathStoreType     StoreType = "filepath"
	GCPStoreType          StoreType = "gcp"
	HerokuStoreType       StoreType = "heroku"
	IncapsulaStoreType    StoreType = "incapsula"
	ThreatxStoreType      StoreType = "threatx"
	VaultStoreType        StoreType = "vault"
)

type RemoteStore interface {
	Update(secret *corev1.Secret) error
}

func NewStore(storeType StoreType) (RemoteStore, error) {
	l := log.WithFields(log.Fields{
		"action": "NewStore",
	})
	l.Debugf("NewStore %s", storeType)
	var store RemoteStore
	switch storeType {
	case ACMStoreType:
		store = &acm.ACMStore{}
	case CloudflareStoreType:
		store = &cloudflare.CloudflareStore{}
	case DigitalOceanStoreType:
		store = &digitalocean.DigitalOceanStore{}
	case FilepathStoreType:
		store = &filepath.FilepathStore{}
	case GCPStoreType:
		store = &gcpcm.GCPStore{}
	case HerokuStoreType:
		store = &heroku.HerokuStore{}
	case IncapsulaStoreType:
		store = &incapsula.IncapsulaStore{}
	case ThreatxStoreType:
		store = &threatx.ThreatXStore{}
	case VaultStoreType:
		store = &vault.VaultStore{}
	default:
		return nil, ErrInvalidStoreType
	}
	return store, nil
}

// maxRetries returns the max number of sync attempts allowed for a secret
// if the secret has a max-sync-attempts annotation
// if the annotation is not present, -1 is returned, indicating unlimited retries
func maxRetries(s *corev1.Secret) int {
	l := log.WithFields(log.Fields{
		"action": "maxRetries",
	})
	l.Debugf("maxRetries %s", s.Name)
	if s.Annotations[state.OperatorName+"/max-sync-attempts"] != "" {
		iv, err := strconv.ParseInt(s.Annotations[state.OperatorName+"/max-sync-attempts"], 10, 64)
		if err != nil {
			l.WithError(err).Errorf("ParseInt error")
			return -1
		}
		return int(iv)
	}
	return -1
}

// consumedRetries returns the number of sync attempts that have been made for a secret
// if the secret has a failed-sync-attempts annotation
// if the annotation is not present, 0 is returned, indicating no retries have been made
func consumedRetries(s *corev1.Secret) int {
	l := log.WithFields(log.Fields{
		"action": "consumedRetries",
	})
	l.Debugf("consumedRetries %s", s.Name)
	if s.Annotations[state.OperatorName+"/failed-sync-attempts"] != "" {
		iv, err := strconv.ParseInt(s.Annotations[state.OperatorName+"/failed-sync-attempts"], 10, 64)
		if err != nil {
			l.WithError(err).Errorf("ParseInt error")
			return 0
		}
		return int(iv)
	}
	return 0
}

// nextRetryTime returns the time when the next sync attempt should be made
// it will return zero time if the secret has not exceeded the max retries
func nextRetryTime(s *corev1.Secret) time.Time {
	l := log.WithFields(log.Fields{
		"action":    "nextRetryTime",
		"namespace": s.Namespace,
		"name":      s.Name,
	})
	l.Debug("nextRetryTime")
	if s.Annotations[state.OperatorName+"/next-retry"] != "" {
		t, err := time.Parse(time.RFC3339, s.Annotations[state.OperatorName+"/next-retry"])
		if err != nil {
			l.WithError(err).Errorf("Parse error")
			return time.Time{}
		}
		l = l.WithFields(log.Fields{
			"next-retry": t,
		})
		l.Debugf("nextRetryTime %s", t)
		return t
	}
	return time.Time{}
}

func readyToRetry(s *corev1.Secret) bool {
	l := log.WithFields(log.Fields{
		"action": "readyToRetry",
	})
	l.Debugf("readyToRetry %s", s.Name)
	maxR := maxRetries(s)
	// if the secret has exceeded the max retries, return false
	consumedR := consumedRetries(s)
	if maxR != -1 && consumedR >= maxR {
		l.Errorf("max retries reached")
		return false
	}
	// if the secret is ready to retry, return true
	nextR := nextRetryTime(s)
	if nextR.IsZero() || time.Now().After(nextR) {
		l.Debugf("ready to retry")
		return true
	}
	// otherwise, return false
	return false
}

func incrementRetries(secretNamespace, secretName string) error {
	l := log.WithFields(log.Fields{
		"action": "incrementRetries",
		"secret": fmt.Sprintf("%s/%s", secretNamespace, secretName),
	})
	l.Debugf("incrementRetries %s/%s", secretNamespace, secretName)
	// get the secret from k8s, since we don't know if data has been changed by a store
	gopt := metav1.GetOptions{}
	secret, err := state.KubeClient.CoreV1().Secrets(secretNamespace).Get(context.Background(), secretName, gopt)
	if err != nil {
		l.WithError(err).Errorf("Get error")
		return err
	}
	if secret.Annotations == nil {
		secret.Annotations = make(map[string]string)
	}
	// increment the failed-sync-attempts annotation
	iv := consumedRetries(secret) + 1
	secret.Annotations[state.OperatorName+"/failed-sync-attempts"] = strconv.Itoa(iv)
	// set the next-retry annotation to the current time plus the delay
	// the delay is a binary exponential backoff, starting at 1 minute, then 2, 4, 8.. up to 32 hours
	delay := time.Duration(1<<uint(iv-1)) * time.Minute
	if delay > 32*time.Hour {
		delay = 32 * time.Hour
	}
	nextRetry := time.Now().Add(delay).Format(time.RFC3339)
	l = l.WithFields(log.Fields{
		"failed-sync-attempts": iv,
		"next-retry":           nextRetry,
	})
	// add the next-retry annotation to the secret
	// this will be evaluated by the readyToRetry function
	// when the next sync attempt is made
	uo := metav1.UpdateOptions{
		FieldManager: state.OperatorName,
	}
	secret.Annotations[state.OperatorName+"/next-retry"] = nextRetry
	_, err = state.KubeClient.CoreV1().Secrets(secretNamespace).Update(context.Background(), secret, uo)
	if err != nil {
		l.WithError(err).Errorf("Update secret error")
		return err
	}
	l.Debugf("incremented retries")
	return nil
}

func resetRetries(secretNamespace, secretName string) error {
	l := log.WithFields(log.Fields{
		"action": "resetRetries",
		"secret": fmt.Sprintf("%s/%s", secretNamespace, secretName),
	})
	l.Debugf("resetRetries %s/%s", secretNamespace, secretName)
	// get the secret from k8s, since we don't know if data has been changed by a store
	gopt := metav1.GetOptions{}
	secret, err := state.KubeClient.CoreV1().Secrets(secretNamespace).Get(context.Background(), secretName, gopt)
	if err != nil {
		l.WithError(err).Errorf("Get error")
		return err
	}
	// remove the failed-sync-attempts annotation
	delete(secret.Annotations, state.OperatorName+"/failed-sync-attempts")
	// remove the next-retry annotation
	delete(secret.Annotations, state.OperatorName+"/next-retry")
	uo := metav1.UpdateOptions{
		FieldManager: state.OperatorName,
	}
	_, err = state.KubeClient.CoreV1().Secrets(secretNamespace).Update(context.Background(), secret, uo)
	if err != nil {
		l.WithError(err).Errorf("Update secret error")
		return err
	}
	return nil
}

func EnabledStores(s *corev1.Secret) []StoreType {
	l := log.WithFields(log.Fields{
		"action": "EnabledStores",
	})
	l.Debugf("checking EnabledStores %s", s.Name)
	var stores []StoreType
	if s.Annotations[state.OperatorName+"/sync-enabled"] != "true" {
		l.Trace("sync not sync-enabled")
		return nil
	}
	// if there is a acm-enabled = true annotation, add acm to the list of stores
	if s.Annotations[state.OperatorName+"/acm-enabled"] == "true" {
		l.Debug("sync-enabled acm")
		stores = append(stores, ACMStoreType)
	}
	// if there is a cloudflare-enabled = true annotation, add cloudflare to the list of stores
	if s.Annotations[state.OperatorName+"/cloudflare-enabled"] == "true" {
		l.Debug("sync-enabled cloudflare")
		stores = append(stores, CloudflareStoreType)
	}
	// if there is a digitalocean-enabled = true annotation, add digitalocean to the list of stores
	if s.Annotations[state.OperatorName+"/digitalocean-enabled"] == "true" {
		l.Debug("sync-enabled digitalocean")
		stores = append(stores, DigitalOceanStoreType)
	}
	// if there is a filepath-enabled = true annotation, add filepath to the list of stores
	if s.Annotations[state.OperatorName+"/filepath-enabled"] == "true" {
		l.Debug("sync-enabled filepath")
		stores = append(stores, FilepathStoreType)
	}
	// if there is a gcp-enabled = true annotation, add gcp to the list of stores
	if s.Annotations[state.OperatorName+"/gcp-enabled"] == "true" {
		l.Debug("sync-enabled gcp")
		stores = append(stores, GCPStoreType)
	}
	// if there is a heroku-enabled = true annotation, add heroku to the list of stores
	if s.Annotations[state.OperatorName+"/heroku-enabled"] == "true" {
		l.Debug("sync-enabled heroku")
		stores = append(stores, HerokuStoreType)
	}
	// if there is a incapsula-site-id annotation, add incapsula to the list of stores
	if s.Annotations[state.OperatorName+"/incapsula-site-id"] != "" {
		l.Debug("sync-enabled incapsula")
		stores = append(stores, IncapsulaStoreType)
	}
	// if there is a threatx-hostname annotation, add threatx to the list of stores
	if s.Annotations[state.OperatorName+"/threatx-hostname"] != "" {
		l.Debug("sync-enabled threatx")
		stores = append(stores, ThreatxStoreType)
	}
	// if there is a vault-addr annotation, add vault to the list of stores
	if s.Annotations[state.OperatorName+"/vault-addr"] != "" {
		l.Debug("sync-enabled vault")
		stores = append(stores, VaultStoreType)
	}
	return stores
}

func SyncSecretToStore(secret *corev1.Secret, store StoreType) error {
	l := log.WithFields(log.Fields{
		"action":    "SyncSecretToStore",
		"store":     store,
		"namespace": secret.Namespace,
		"secret":    secret.Name,
	})
	l.Debugf("syncing store %s", store)
	rs, err := NewStore(store)
	if err != nil {
		l.WithError(err).Error("NewStore error")
		metrics.SetFailure(secret.Namespace, secret.Name, string(store))
		state.EventRecorder.Event(secret, corev1.EventTypeWarning, "SyncFailed", fmt.Sprintf("Secret sync failed to store %s", store))
		return fmt.Errorf("error creating store %s: %v", store, err)
	}
	if err := rs.Update(secret); err != nil {
		l.WithError(err).Error("sync error")
		metrics.SetFailure(secret.Namespace, secret.Name, string(store))
		state.EventRecorder.Event(secret, corev1.EventTypeWarning, "SyncFailed", fmt.Sprintf("Secret sync failed to store %s", store))
		return fmt.Errorf("error syncing secret %s/%s to store %s: %v", secret.Namespace, secret.Name, store, err)
	}
	metrics.SetSuccess(secret.Namespace, secret.Name, string(store))
	state.EventRecorder.Event(secret, corev1.EventTypeNormal, "Synced", fmt.Sprintf("Secret synced to %s", store))
	return nil
}

func HandleSecret(s *corev1.Secret) error {
	l := log.WithFields(log.Fields{
		"action":    "HandleSecret",
		"namespace": s.Namespace,
		"name":      s.Name,
	})
	l.Debugf("HandleSecret %s/%s", s.Namespace, s.Name)
	// ensure we haven't exceeded the allotted retries
	if !readyToRetry(s) {
		l.Debug("not ready to retry")
		return nil
	}
	// get the list of stores enabled for this secret
	stores := EnabledStores(s)
	if len(stores) == 0 {
		l.Debug("no stores enabled")
		return nil
	}
	// check if the secret has changed since last sync
	if !state.CacheChanged(s) {
		l.Debug("cache not changed")
		return nil
	}
	// sync the secret to each enabled store in parallel
	errors := make(chan error, len(stores))
	for _, store := range stores {
		go func(store StoreType) {
			errors <- SyncSecretToStore(s, store)
		}(store)
	}
	// wait for all stores to finish syncing
	// if a store returns an error, return the error
	// but only after all stores have finished syncing
	var errs []error
	for i := 0; i < len(stores); i++ {
		err := <-errors
		if err != nil {
			l.WithError(err).Errorf("SyncCertToStore error")
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		// increment the failed-sync-attempts annotation
		if err := incrementRetries(s.Namespace, s.Name); err != nil {
			l.WithError(err).Errorf("incrementRetries error")
		}
		state.EventRecorder.Event(s, corev1.EventTypeWarning, "SyncFailed", "Secret sync failed")
		return fmt.Errorf("errors syncing secret %s/%s: %v", s.Namespace, s.Name, errs)
	} else {
		// reset the failed-sync-attempts annotation
		if err := resetRetries(s.Namespace, s.Name); err != nil {
			l.WithError(err).Errorf("resetRetries error")
		}
	}
	// if the sync was a success, add the secret to the cache
	state.Cache(s)
	eventMsg := fmt.Sprintf("Secret synced to %d store%s", len(stores), func() string {
		if len(stores) == 1 {
			return ""
		}
		return "s"
	}())
	state.EventRecorder.Event(s, corev1.EventTypeNormal, "Synced", eventMsg)
	return nil
}
