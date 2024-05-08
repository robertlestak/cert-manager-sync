package certmanagersync

import (
	"context"
	"errors"
	"fmt"
	"strconv"

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
		return nil, errors.New("invalid store type")
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

func incrementRetries(secretNamespace, secretName string) error {
	l := log.WithFields(log.Fields{
		"action": "incrementRetries",
	})
	l.Debugf("incrementRetries %s/%s", secretNamespace, secretName)
	// get the secret from k8s, since we don't know if data has been changed by a store
	gopt := metav1.GetOptions{}
	secret, err := state.KubeClient.CoreV1().Secrets(secretNamespace).Get(context.Background(), secretName, gopt)
	if err != nil {
		l.WithError(err).Errorf("Get error")
		return err
	}
	// increment the failed-sync-attempts annotation
	iv := consumedRetries(secret) + 1
	secret.Annotations[state.OperatorName+"/failed-sync-attempts"] = strconv.Itoa(iv)
	_, err = state.KubeClient.CoreV1().Secrets(secretNamespace).Update(context.Background(), secret, metav1.UpdateOptions{})
	if err != nil {
		l.WithError(err).Errorf("Update error")
		return err
	}
	return nil
}

func resetRetries(secretNamespace, secretName string) error {
	l := log.WithFields(log.Fields{
		"action": "resetRetries",
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
	_, err = state.KubeClient.CoreV1().Secrets(secretNamespace).Update(context.Background(), secret, metav1.UpdateOptions{})
	if err != nil {
		l.WithError(err).Errorf("Update error")
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
		l.Debug("sync not sync-enabled")
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
		"action": "SyncSecretToStore",
	})
	l.Debugf("syncing store %s", store)
	rs, err := NewStore(store)
	if err != nil {
		l.WithError(err).Errorf("NewStore error")
		return err
	}
	if err := rs.Update(secret); err != nil {
		l.WithError(err).Errorf("Update error")
		return err
	}
	return nil
}

func HandleSecret(s *corev1.Secret) error {
	l := log.WithFields(log.Fields{
		"action": "HandleSecret",
	})
	l.Debugf("HandleSecret %s", s.Name)
	// ensure we haven't exceeded the allotted retries
	maxR := maxRetries(s)
	consumedR := consumedRetries(s)
	if maxR != -1 && consumedR >= maxR {
		l.Errorf("max retries reached")
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
		return fmt.Errorf("errors syncing secret %s/%s to stores: %v", s.Namespace, s.Name, errs)
	} else {
		// reset the failed-sync-attempts annotation
		if err := resetRetries(s.Namespace, s.Name); err != nil {
			l.WithError(err).Errorf("resetRetries error")
		}
	}
	// if the sync was a success, add the secret to the cache
	state.AddToCache(s)
	return nil
}
