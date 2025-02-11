package tlssecret

import (
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"

	"github.com/robertlestak/cert-manager-sync/pkg/state"
)

type GenericSecretSyncConfig struct {
	Store   string
	Index   int
	Config  map[string]string
	Updates map[string]string
}

func ParseStoreAnnotation(k string) (string, string) {
	// we expect the annotation key to be in the format:
	// OperatorName + "/<store>-" + <key>
	// we want to return <store> and <key>
	if !strings.HasPrefix(k, state.OperatorName+"/") {
		return "", ""
	}
	parts := strings.Split(k, "/")
	if len(parts) != 2 || parts[1] == "" {
		return "", ""
	}
	storeParts := strings.SplitN(parts[1], "-", 2)
	if len(storeParts) != 2 || storeParts[1] == "" {
		return "", ""
	}
	return storeParts[0], storeParts[1]
}

func GetSecretStoresMeta(s *v1.Secret) map[string][]map[string]string {
	// find all annotations which have the prefix:
	// OperatorName + "/<store>-" + <key> = <value>
	// and return a list of SecretStoreMeta
	// where Name is <store> and Meta is a map of <key> to <value>
	// for all annotations with the prefix
	stores := make(map[string][]map[string]string)
	for k, v := range s.Annotations {
		// allow unknown store annotations but trigger event later
		store, key := ParseStoreAnnotation(k)
		if store == "" {
			continue
		}
		if _, ok := stores[store]; !ok {
			stores[store] = []map[string]string{}
		}
		stores[store] = append(stores[store], map[string]string{key: v})
	}
	return stores
}

func SecretMetaToGenericSecretSyncConfig(meta map[string][]map[string]string) ([]*GenericSecretSyncConfig, error) {
	// for each store, the keys will be a provider-specific key, eg, "arn-role"
	// however to enable multiple configurations for a single secret, users can
	// suffix a key with an index, eg "arn-role.0"
	// that way, all the keys with the same index will be grouped together
	// we need to remove the .0 suffix from the string, so the key is "arn-role"
	// and the index is 0
	// keys without an index will have an index of -1, which is the default
	configs := []*GenericSecretSyncConfig{}
	for store, keys := range meta {
		for _, key := range keys {
			for k, v := range key {
				parts := strings.Split(k, ".")
				index := -1
				if len(parts) == 2 {
					k = parts[0]
					// parse the second part as the index
					pv, err := strconv.Atoi(parts[1])
					if err != nil {
						return nil, err
					}
					index = pv
				}
				// if there is a config with the same store and index, we should merge the configs
				// otherwise create
				found := false
				for i, c := range configs {
					if c.Store == store && c.Index == index {
						found = true
						configs[i].Config[k] = v
					}
				}
				if !found {
					configs = append(configs, &GenericSecretSyncConfig{
						Store:  store,
						Index:  index,
						Config: map[string]string{k: v},
					})
				}
			}
		}
	}
	return configs, nil
}

func SyncsForStore(sec *v1.Secret, storeName string) ([]*GenericSecretSyncConfig, error) {
	meta := GetSecretStoresMeta(sec)
	configs, err := SecretMetaToGenericSecretSyncConfig(meta)
	if err != nil {
		return nil, err
	}
	syncs := []*GenericSecretSyncConfig{}
	for _, c := range configs {
		if c.Store == storeName {
			syncs = append(syncs, c)
		}
	}
	return syncs, nil
}

func (c *Certificate) SyncsForStore(storeName string) ([]*GenericSecretSyncConfig, error) {
	var syncs []*GenericSecretSyncConfig
	for _, s := range c.Syncs {
		if s.Store == storeName {
			syncs = append(syncs, s)
		}
	}
	return syncs, nil
}

func SyncsForSecret(sec *v1.Secret) ([]*GenericSecretSyncConfig, error) {
	meta := GetSecretStoresMeta(sec)
	configs, err := SecretMetaToGenericSecretSyncConfig(meta)
	if err != nil {
		return nil, err
	}
	return configs, nil
}

func AnnotationUpdates(c *Certificate) map[string]string {
	l := log.WithFields(log.Fields{
		"action":    "AnnotationUpdates",
		"syncCount": len(c.Syncs),
	})
	l.Debug("start")
	defer l.Debug("end")
	updates := make(map[string]string)
	// loop through the syncs
	// if it has updates, we need to build back up the annotation key
	// and value
	for _, s := range c.Syncs {
		ll := l.WithFields(log.Fields{
			"store": s.Store,
			"index": s.Index,
		})
		ll.Debug("sync")
		if len(s.Updates) == 0 {
			ll.Debug("no updates")
			continue
		}
		if s.Index == -1 {
			for k, v := range s.Updates {
				updates[state.OperatorName+"/"+s.Store+"-"+k] = v
				ll.WithFields(log.Fields{
					"key": k,
					"val": v,
				}).Debug("update")
			}
		} else {
			for k, v := range s.Updates {
				updates[state.OperatorName+"/"+s.Store+"-"+k+"."+strconv.Itoa(s.Index)] = v
				ll.WithFields(log.Fields{
					"key": k,
					"val": v,
				}).Debug("update")
			}
		}
	}
	l = l.WithFields(log.Fields{
		"updates": updates,
	})
	l.Debug("return")
	return updates
}
