package vault

import (
	"cmp"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
)

type VaultStore struct {
	Addr         string
	Namespace    string
	Role         string
	AuthMethod   string
	Path         string
	Base64Decode bool
	KubeToken    string      // auto-filled
	Client       *api.Client // auto-filled
	Token        string      // auto-filled
}

func kubeToken() string {
	return cmp.Or(os.Getenv("KUBE_TOKEN"), "/var/run/secrets/kubernetes.io/serviceaccount/token")
}

// NewClients creates and returns a new vault client with a valid token or error
func (s *VaultStore) NewClient() (*api.Client, error) {
	l := log.WithFields(log.Fields{
		"vaultAddr": s.Addr,
		"action":    "vault.NewClient",
	})
	l.Debugf("vault.NewClient")
	config := &api.Config{
		Address: s.Addr,
	}
	var err error
	s.Client, err = api.NewClient(config)
	if err != nil {
		l.WithError(err).Errorf("vault.NewClient error")
		return s.Client, err
	}
	if s.Namespace != "" {
		l.Debugf("vault.NewClient using namespace %s", s.Namespace)
		s.Client.SetNamespace(s.Namespace)
	}
	if kubeToken() != "" {
		l.Debugf("vault.NewClient using KUBE_TOKEN")
		fd, err := os.ReadFile(kubeToken())
		if err != nil {
			l.WithError(err).Errorf("vault.NewClient error")
			return s.Client, err
		}
		s.KubeToken = string(fd)
	}
	_, terr := s.NewToken()
	if terr != nil {
		l.WithError(terr).Errorf("vault.NewClient error")
		return s.Client, terr
	}
	return s.Client, err
}

// Login creates a vault token with the k8s auth provider
func (s *VaultStore) Login() (string, error) {
	l := log.WithFields(log.Fields{
		"vaultAddr":  s.Addr,
		"action":     "vault.Login",
		"role":       s.Role,
		"authMethod": s.AuthMethod,
	})
	l.Debugf("vault.Login")
	options := map[string]interface{}{
		"role": s.Role,
		"jwt":  s.KubeToken,
	}
	path := fmt.Sprintf("auth/%s/login", s.AuthMethod)
	secret, err := s.Client.Logical().Write(path, options)
	if err != nil {
		l.WithError(err).Errorf("vault.Login error")
		return "", err
	}
	s.Token = secret.Auth.ClientToken
	l.Debugf("vault.Login success")
	s.Client.SetToken(s.Token)
	return s.Token, nil
}

// NewToken generate a new token for session. If LOCAL env var is set and the token is as well, the login is
// skipped and the token is used instead.
func (s *VaultStore) NewToken() (string, error) {
	l := log.WithFields(log.Fields{
		"vaultAddr": s.Addr,
		"action":    "vault.NewToken",
	})
	l.Debugf("vault.NewToken")
	if os.Getenv("LOCAL") != "" && os.Getenv("VAULT_TOKEN") != "" {
		l.Debugf("vault.NewToken using local token")
		s.Token = os.Getenv("VAULT_TOKEN")
		s.Client.SetToken(s.Token)
		return s.Token, nil
	}
	l.Debugf("vault.NewToken using login")
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
func (s *VaultStore) WriteSecret(sec map[string]interface{}) (map[string]interface{}, error) {
	if s == nil {
		return nil, errors.New("vault client required")
	}
	l := log.WithFields(log.Fields{
		"vaultAddr": s.Addr,
		"action":    "vault.WriteSecret",
	})
	l.Debugf("vault.WriteSecret")
	var secrets map[string]interface{}
	pp := strings.Split(s.Path, "/")
	if len(pp) < 2 {
		return secrets, errors.New("secret path must be in kv/path/to/secret format")
	}
	pp = insertSliceString(pp, 1, "data")
	if len(pp) == 0 {
		return secrets, errors.New("secret path required")
	}
	if pp == nil {
		s.Path = "/"
	} else {
		s.Path = strings.Join(pp, "/")
	}
	l.Debugf("vault.WriteSecret writing to %s", s.Path)
	if s.Path == "" {
		return secrets, errors.New("secret path required")
	}
	vd := map[string]interface{}{
		"data": sec,
	}
	_, err := s.Client.Logical().Write(s.Path, vd)
	if err != nil {
		l.WithError(err).Errorf("vault.WriteSecret error")
		return secrets, err
	}
	return secrets, nil
}

func (s *VaultStore) ParseCertificate(c *tlssecret.Certificate) error {
	l := log.WithFields(log.Fields{
		"action": "ParseCertificate",
	})
	l.Debugf("ParseCertificate")
	if c.Annotations[state.OperatorName+"/vault-path"] != "" {
		s.Path = c.Annotations[state.OperatorName+"/vault-path"]
	}
	if c.Annotations[state.OperatorName+"/vault-addr"] != "" {
		s.Addr = c.Annotations[state.OperatorName+"/vault-addr"]
	}
	if c.Annotations[state.OperatorName+"/vault-namespace"] != "" {
		s.Namespace = c.Annotations[state.OperatorName+"/vault-namespace"]
	}
	if c.Annotations[state.OperatorName+"/vault-role"] != "" {
		s.Role = c.Annotations[state.OperatorName+"/vault-role"]
	}
	if c.Annotations[state.OperatorName+"/vault-auth-method"] != "" {
		s.AuthMethod = c.Annotations[state.OperatorName+"/vault-auth-method"]
	}
	if c.Annotations[state.OperatorName+"/vault-base64-decode"] == "true" || c.Annotations[state.OperatorName+"/vault-b64dec"] == "true" {
		s.Base64Decode = true
	}
	return nil
}

func writeSecretValue(value []byte, asString bool) any {
	if asString {
		return string(value)
	}
	return value
}

func (s *VaultStore) Update(secret *corev1.Secret) error {
	l := log.WithFields(log.Fields{
		"action":          "Update",
		"store":           "vault",
		"secretName":      secret.ObjectMeta.Name,
		"secretNamespace": secret.ObjectMeta.Namespace,
	})
	l.Debugf("Update")
	c := tlssecret.ParseSecret(secret)
	if err := s.ParseCertificate(c); err != nil {
		l.WithError(err).Errorf("vault.ParseCertificate error")
		return err
	}
	var vid string
	if s.Namespace != "" {
		vid = fmt.Sprintf("%s %s/%s", s.Addr, s.Namespace, s.Path)
	} else {
		vid = fmt.Sprintf("%s %s", s.Addr, s.Path)
	}
	l = l.WithFields(log.Fields{
		"vaultPath":       s.Path,
		"vaultAddr":       s.Addr,
		"vaultNamespace":  s.Namespace,
		"vaultRole":       s.Role,
		"vaultAuthMethod": s.AuthMethod,
		"id":              vid,
	})
	_, cerr := s.NewClient()
	if cerr != nil {
		l.WithError(cerr).Errorf("vault.NewClient error")
		return cerr
	}
	_, err := s.NewToken()
	if err != nil {
		l.WithError(err).Errorf("vault.NewToken error")
		return err
	}
	cd := map[string]interface{}{
		"tls.crt": writeSecretValue(c.Certificate, s.Base64Decode),
		"tls.key": writeSecretValue(c.Key, s.Base64Decode),
	}

	// if there is a CA, add it to the secret
	if len(c.Ca) > 0 {
		cd["ca.crt"] = writeSecretValue(c.Ca, s.Base64Decode)
	}
	_, err = s.WriteSecret(cd)
	if err != nil {
		l.WithError(err).Errorf("sync error")
		return err
	}
	l.Info("certificate synced")
	return nil
}
