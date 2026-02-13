package types

import "errors"

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
	IncapsulaStoreType    StoreType = "incapsula"
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
	IncapsulaStoreType,
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
