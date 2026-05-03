package certmanagersync

import (
	"context"

	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
)

// fakeStore is a test double satisfying both RemoteStore and DeletableRemoteStore.
type fakeStore struct {
	syncErr   error
	deleteErr error
	syncCnt   int
	deleteCnt int
	gotConfig tlssecret.GenericSecretSyncConfig
}

func (f *fakeStore) Sync(_ *tlssecret.Certificate) (map[string]string, error) {
	f.syncCnt++
	return nil, f.syncErr
}

func (f *fakeStore) FromConfig(c tlssecret.GenericSecretSyncConfig) error {
	f.gotConfig = c
	return nil
}

func (f *fakeStore) Delete(_ context.Context) error {
	f.deleteCnt++
	return f.deleteErr
}

// nonDeletableFakeStore satisfies RemoteStore but NOT DeletableRemoteStore.
// Used to verify that stores without delete support are silently skipped
// during HandleSecretDelete.
type nonDeletableFakeStore struct {
	syncErr   error
	syncCnt   int
	gotConfig tlssecret.GenericSecretSyncConfig
}

func (f *nonDeletableFakeStore) Sync(_ *tlssecret.Certificate) (map[string]string, error) {
	f.syncCnt++
	return nil, f.syncErr
}

func (f *nonDeletableFakeStore) FromConfig(c tlssecret.GenericSecretSyncConfig) error {
	f.gotConfig = c
	return nil
}
