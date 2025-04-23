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
	IncapsulaStoreType    StoreType = "incapsula"
	ThreatxStoreType      StoreType = "threatx"
	VaultStoreType        StoreType = "vault"
	SlackStoreType        StoreType = "slack"
)

var EnabledStores = []StoreType{
	ACMStoreType,
	CloudflareStoreType,
	DigitalOceanStoreType,
	FilepathStoreType,
	GCPStoreType,
	HerokuStoreType,
	IncapsulaStoreType,
	ThreatxStoreType,
	VaultStoreType,
	SlackStoreType,
}

func IsValidStoreType(storeType string) bool {
	for _, s := range EnabledStores {
		if storeType == string(s) {
			return true
		}
	}
	return false
}