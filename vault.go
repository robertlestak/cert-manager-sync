package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
)

type VaultSecret struct {
	Addr       string
	Role       string
	AuthMethod string
	Path       string
	KubeToken  string      // auto-filled
	Client     *api.Client // auto-filled
	Token      string      // auto-filled
}

// NewClients creates and returns a new vault client with a valid token or error
func (s *VaultSecret) NewClient() (*api.Client, error) {
	l := log.WithFields(log.Fields{
		"vaultAddr": s.Addr,
		"action":    "vault.NewClient",
	})
	l.Printf("vault.NewClient")
	config := &api.Config{
		Address: s.Addr,
	}
	var err error
	s.Client, err = api.NewClient(config)
	if err != nil {
		l.Printf("vault.NewClient error: %v\n", err)
		return s.Client, err
	}
	if os.Getenv("KUBE_TOKEN") != "" {
		l.Printf("vault.NewClient using KUBE_TOKEN")
		fd, err := ioutil.ReadFile(os.Getenv("KUBE_TOKEN"))
		if err != nil {
			l.Printf("vault.NewClient error: %v\n", err)
			return s.Client, err
		}
		s.KubeToken = string(fd)
	}
	_, terr := s.NewToken()
	if terr != nil {
		l.Printf("vault.NewClient error: %v\n", terr)
		return s.Client, terr
	}
	return s.Client, err
}

// Login creates a vault token with the k8s auth provider
func (s *VaultSecret) Login() (string, error) {
	l := log.WithFields(log.Fields{
		"vaultAddr":  s.Addr,
		"action":     "vault.Login",
		"role":       s.Role,
		"authMethod": s.AuthMethod,
	})
	l.Printf("vault.Login")
	options := map[string]interface{}{
		"role": s.Role,
		"jwt":  s.KubeToken,
	}
	path := fmt.Sprintf("auth/%s/login", s.AuthMethod)
	secret, err := s.Client.Logical().Write(path, options)
	if err != nil {
		l.Printf("vault.Login(%s) error: %v\n", s.AuthMethod, err)
		return "", err
	}
	s.Token = secret.Auth.ClientToken
	l.Printf("vault.Login(%s) success\n", s.AuthMethod)
	s.Client.SetToken(s.Token)
	return s.Token, nil
}

// NewToken generate a new token for session. If LOCAL env var is set and the token is as well, the login is
// skipped and the token is used instead.
func (s *VaultSecret) NewToken() (string, error) {
	l := log.WithFields(log.Fields{
		"vaultAddr": s.Addr,
		"action":    "vault.NewToken",
	})
	l.Printf("vault.NewToken")
	if os.Getenv("LOCAL") != "" && os.Getenv("VAULT_TOKEN") != "" {
		l.Printf("vault.NewToken using local token")
		s.Token = os.Getenv("VAULT_TOKEN")
		s.Client.SetToken(s.Token)
		return s.Token, nil
	}
	l.Printf("vault.NewToken calling Login")
	return s.Login()
}

func insertSliceString(a []string, index int, value string) []string {
	if len(a) == index { // nil or empty slice or after last element
		return append(a, value)
	}
	a = append(a[:index+1], a[index:]...) // index < len(a)
	a[index] = value
	return a
}

// WriteSecret writes a secret to Vault VaultClient at path p with secret value s
func (s *VaultSecret) WriteSecret(sec map[string]interface{}) (map[string]interface{}, error) {
	var secrets map[string]interface{}
	pp := strings.Split(s.Path, "/")
	if len(pp) < 2 {
		return secrets, errors.New("secret path must be in kv/path/to/secret format")
	}
	pp = insertSliceString(pp, 1, "data")
	s.Path = strings.Join(pp, "/")
	log.Printf("vault.PutSecret(%+v)\n", s.Path)
	if s == nil {
		return secrets, errors.New("secret data required")
	}
	if s.Path == "" {
		return secrets, errors.New("secret path required")
	}
	s.Client.AddHeader("x-vault-sync", "true")
	vd := map[string]interface{}{
		"data": sec,
	}
	_, err := s.Client.Logical().Write(s.Path, vd)
	if err != nil {
		log.Printf("vault.PutSecret(%+v) error: %v\n", s.Path, err)
		return secrets, err
	}
	return secrets, nil
}

// VaultCerts accepts a slice of Secrets and returns only those configured
// for replication to HashiCorp Vault
func VaultCerts(s []corev1.Secret) []corev1.Secret {
	var c []corev1.Secret
	for _, v := range s {
		if v.Annotations[operatorName+"/vault-path"] != "" && cacheChanged(v) {
			c = append(c, v)
		}
	}
	return c
}

// handleVaultCerts handles the sync of all Vault-enabled certs
func handleVaultCerts(ss []corev1.Secret) {
	ss = VaultCerts(ss)
	l := log.WithFields(
		log.Fields{
			"action": "handleVaultCerts",
		},
	)
	l.Print("handleVaultCerts")
	for i, s := range ss {
		l.Debugf("processing secret %s (%d/%d)", s.ObjectMeta.Name, i+1, len(ss))
		vs := VaultSecret{
			Addr:       s.Annotations[operatorName+"/vault-addr"],
			Path:       s.Annotations[operatorName+"/vault-path"],
			Role:       s.Annotations[operatorName+"/vault-role"],
			AuthMethod: s.Annotations[operatorName+"/vault-auth-method"],
		}
		c := secretToCert(s)
		if c == nil {
			l.Errorf("secretToCert(%s) error: cert required", s.ObjectMeta.Name)
			continue
		}
		_, cerr := vs.NewClient()
		if cerr != nil {
			l.Errorf("vault.NewClient(%s) error: %v", s.ObjectMeta.Name, cerr)
			continue
		}
		_, err := vs.NewToken()
		if err != nil {
			l.Errorf("vault.NewToken(%s) error: %v", s.ObjectMeta.Name, err)
			continue
		}
		cd := map[string]interface{}{
			"certificate": c.Certificate,
			"chain":       c.Chain,
			"key":         c.Key,
		}
		_, err = vs.WriteSecret(cd)
		if err != nil {
			l.Errorf("vault.WriteSecret(%s) error: %v", s.ObjectMeta.Name, err)
			continue
		}
		l.Debugf("vault.WriteSecret(%s) success", vs.Path)
		addToCache(c)
	}
}
