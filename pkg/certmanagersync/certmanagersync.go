package certmanagersync

import (
	"errors"
	"fmt"

	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/stores/acm"
	"github.com/robertlestak/cert-manager-sync/stores/digitalocean"
	"github.com/robertlestak/cert-manager-sync/stores/gcpcm"
	"github.com/robertlestak/cert-manager-sync/stores/heroku"
	"github.com/robertlestak/cert-manager-sync/stores/incapsula"
	"github.com/robertlestak/cert-manager-sync/stores/threatx"
	"github.com/robertlestak/cert-manager-sync/stores/vault"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
)

type StoreType string

const (
	ACMStoreType          StoreType = "acm"
	DigitalOceanStoreType StoreType = "digitalocean"
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
	var err error
	switch storeType {
	case ACMStoreType:
		store = &acm.ACMStore{}
	case DigitalOceanStoreType:
		store = &digitalocean.DigitalOceanStore{}
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
	if err != nil {
		l.WithError(err).Errorf("vault.NewStore error")
		return nil, err
	}
	return store, nil
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
	// if there is a vault-addr annotation, add vault to the list of stores
	if s.Annotations[state.OperatorName+"/vault-addr"] != "" {
		l.Debug("sync-enabled vault")
		stores = append(stores, VaultStoreType)
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
	// if there is a acm-enabled = true annotation, add acm to the list of stores
	if s.Annotations[state.OperatorName+"/acm-enabled"] == "true" {
		l.Debug("sync-enabled acm")
		stores = append(stores, ACMStoreType)
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
	// if there is a digitalocean-enabled = true annotation, add digitalocean to the list of stores
	if s.Annotations[state.OperatorName+"/digitalocean-enabled"] == "true" {
		l.Debug("sync-enabled digitalocean")
		stores = append(stores, DigitalOceanStoreType)
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
		return fmt.Errorf("errors syncing secret %s/%s to stores: %v", s.Namespace, s.Name, errs)
	}
	// if the sync was a success, add the secret to the cache
	state.AddToCache(s)
	return nil
}
