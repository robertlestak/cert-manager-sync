package types

import (
	"errors"
	"slices"
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
	HetznerCloudStoreType StoreType = "hetznercloud"
	ImpervaStoreType      StoreType = "imperva"
	IncapsulaStoreType    StoreType = "incapsula" // Deprecated: Use ImpervaStoreType
	ThreatxStoreType      StoreType = "threatx"
	VaultStoreType        StoreType = "vault"
)

var EnabledStores = []StoreType{
	ACMStoreType,
	CloudflareStoreType,
	DigitalOceanStoreType,
	FilepathStoreType,
	GCPStoreType,
	HerokuStoreType,
	HetznerCloudStoreType,
	ImpervaStoreType,
	IncapsulaStoreType, // Backwards compatibility
	ThreatxStoreType,
	VaultStoreType,
}

func IsValidStoreType(storeType string) bool {
	for _, s := range EnabledStores {
		if storeType == string(s) {
			return true
		}
	}
	return false
}

// ManagedOutputKeys maps a store type to the config keys the operator writes
// back to the synced secret after a successful sync (the remote resource
// identifier, e.g. cloudflare's cert-id). These are operator output, not user
// input. Keep this in sync with each store's Sync() return value — the keys
// here must match the map keys returned by the corresponding store.
var ManagedOutputKeys = map[StoreType][]string{
	ACMStoreType:          {"certificate-arn"},
	CloudflareStoreType:   {"cert-id"},
	DigitalOceanStoreType: {"cert-id"},
	GCPStoreType:          {"certificate-name"},
	HerokuStoreType:       {"cert-name"},
	HetznerCloudStoreType: {"cert-id"},
}

// IsManagedOutputKey reports whether the given store and config key identify an
// operator-managed write-back annotation (see ManagedOutputKeys).
func IsManagedOutputKey(store, key string) bool {
	return slices.Contains(ManagedOutputKeys[StoreType(store)], key)
}
