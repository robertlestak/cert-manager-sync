package certmanagersync

import (
	"testing"

	cmtypes "github.com/robertlestak/cert-manager-sync/internal/types"
)

// TestStoresImplementDelete locks in which built-in stores must implement
// DeletableRemoteStore. If a store gains or loses Delete support, this test
// fails so the change is intentional and reviewed.
func TestStoresImplementDelete(t *testing.T) {
	deletable := []cmtypes.StoreType{
		cmtypes.ACMStoreType,
		cmtypes.CloudflareStoreType,
		cmtypes.DigitalOceanStoreType,
		cmtypes.FilepathStoreType,
		cmtypes.GCPStoreType,
		cmtypes.HerokuStoreType,
		cmtypes.HetznerCloudStoreType,
		cmtypes.VaultStoreType,
	}
	for _, st := range deletable {
		t.Run(string(st), func(t *testing.T) {
			rs, err := NewStore(st)
			if err != nil {
				t.Fatalf("NewStore(%s): %v", st, err)
			}
			if _, ok := rs.(DeletableRemoteStore); !ok {
				t.Fatalf("store %s does not implement DeletableRemoteStore", st)
			}
		})
	}

	// Confirm intentional non-implementations.
	nonDeletable := []cmtypes.StoreType{
		cmtypes.ImpervaStoreType,
		cmtypes.IncapsulaStoreType,
		cmtypes.ThreatxStoreType,
	}
	for _, st := range nonDeletable {
		t.Run(string(st)+"_does_not_delete", func(t *testing.T) {
			rs, err := NewStore(st)
			if err != nil {
				t.Fatalf("NewStore(%s): %v", st, err)
			}
			if _, ok := rs.(DeletableRemoteStore); ok {
				t.Fatalf("store %s unexpectedly implements DeletableRemoteStore; update the documented v1 scope or move it to the deletable list", st)
			}
		})
	}
}
