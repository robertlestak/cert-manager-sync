package stores

import (
	"errors"

	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
)

var (
	ErrSecretNameNotFound      = errors.New("secret name not found in certificate annotations")
	ErrSecretNamespaceNotFound = errors.New("secret namespace not found in certificate annotations")
	ErrInvalidStoreType        = errors.New("invalid store type")
)

type StoreCreatorFunc func(config tlssecret.GenericSecretSyncConfig) (RemoteStore, error)

func (f StoreCreatorFunc) FromConfig(config tlssecret.GenericSecretSyncConfig) (RemoteStore, error) {
	return f(config)
}

type StoreCreator interface {
	FromConfig(config tlssecret.GenericSecretSyncConfig) (RemoteStore, error)
}

type RemoteStore interface {
	Sync(cert *tlssecret.Certificate) (map[string]string, error)
}

var storeCreatorFactories = map[string]StoreCreator{}

func Register(t string, c StoreCreator) {
	if _, ok := storeCreatorFactories[t]; ok {
		panic("duplicate store creator " + string(t))
	}
	storeCreatorFactories[t] = c
}

func New(t string, config tlssecret.GenericSecretSyncConfig) (RemoteStore, error) {
	c, ok := storeCreatorFactories[t]
	if !ok {
		return nil, ErrInvalidStoreType
	}
	return c.FromConfig(config)
}
