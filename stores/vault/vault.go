package vault

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"software.sslmate.com/src/go-pkcs12"
)

type VaultStore struct {
	Addr                      string
	Namespace                 string
	Role                      string
	AuthMethod                string
	Path                      string
	Base64Decode              bool
	PKCS12                    bool
	PKCS12PassSecret          string      // Name of the secret containing the password
	PKCS12PassSecretKey       string      // Key in the secret containing the password
	PKCS12PassSecretNamespace string      // Namespace of the secret containing the password
	KubeToken                 string      // auto-filled
	Client                    *api.Client // auto-filled
	Token                     string      // auto-filled
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

func (s *VaultStore) FromConfig(c tlssecret.GenericSecretSyncConfig) error {
	l := log.WithFields(log.Fields{
		"action": "FromConfig",
	})
	l.Debugf("FromConfig")
	if c.Config["path"] != "" {
		s.Path = c.Config["path"]
	}
	if c.Config["addr"] != "" {
		s.Addr = c.Config["addr"]
	}
	if c.Config["namespace"] != "" {
		s.Namespace = c.Config["namespace"]
	}
	if c.Config["role"] != "" {
		s.Role = c.Config["role"]
	}
	if c.Config["auth-method"] != "" {
		s.AuthMethod = c.Config["auth-method"]
	}
	if c.Config["base64-decode"] == "true" || c.Config["b64dec"] == "true" {
		s.Base64Decode = true
	}
	if c.Config["pkcs12"] == "true" {
		s.PKCS12 = true
	}
	// Secret reference for password
	if c.Config["pkcs12-password-secret"] != "" {
		s.PKCS12PassSecret = c.Config["pkcs12-password-secret"]
	}
	if c.Config["pkcs12-password-secret-key"] != "" {
		s.PKCS12PassSecretKey = c.Config["pkcs12-password-secret-key"]
	} else if s.PKCS12PassSecret != "" {
		// Default key if not specified
		s.PKCS12PassSecretKey = "password"
	}
	if c.Config["pkcs12-password-secret-namespace"] != "" {
		s.PKCS12PassSecretNamespace = c.Config["pkcs12-password-secret-namespace"]
	} else if s.PKCS12PassSecret != "" {
		// Default to the same namespace as the certificate
		// We'll set this in the Sync method where we have access to the certificate namespace
	}
	return nil
}

func writeSecretValue(value []byte, asString bool) any {
	if asString {
		return string(value)
	}
	return value
}

// getPasswordFromSecret retrieves the PKCS#12 password from a Kubernetes secret
func (s *VaultStore) getPasswordFromSecret(c *tlssecret.Certificate) (string, error) {
	l := log.WithFields(log.Fields{
		"action":    "getPasswordFromSecret",
		"secret":    s.PKCS12PassSecret,
		"namespace": s.PKCS12PassSecretNamespace,
	})
	l.Debug("Retrieving PKCS#12 password from secret")

	// If no secret is specified, return empty string
	if s.PKCS12PassSecret == "" {
		return "", nil
	}

	// Get the secret from Kubernetes
	secret, err := state.KubeClient.CoreV1().Secrets(s.PKCS12PassSecretNamespace).Get(
		context.Background(),
		s.PKCS12PassSecret,
		metav1.GetOptions{},
	)
	if err != nil {
		l.WithError(err).Error("Failed to get secret containing PKCS#12 password")
		return "", err
	}

	// Get the password from the secret
	passwordBytes, ok := secret.Data[s.PKCS12PassSecretKey]
	if !ok {
		err := fmt.Errorf("key %s not found in secret %s/%s",
			s.PKCS12PassSecretKey, s.PKCS12PassSecretNamespace, s.PKCS12PassSecret)
		l.WithError(err).Error("Failed to get PKCS#12 password from secret")
		return "", err
	}

	return string(passwordBytes), nil
}

// convertToPKCS12WithPassword converts PEM certificate and key to PKCS#12 format with the given password
// If the password is empty, a random one will be generated
func (s *VaultStore) convertToPKCS12WithPassword(cert []byte, key []byte, ca []byte, password string) ([]byte, string, error) {
	l := log.WithFields(log.Fields{
		"action": "convertToPKCS12WithPassword",
	})
	l.Debug("Converting certificate to PKCS#12 format")

	// Parse the certificate
	certBlock, _ := pem.Decode(cert)
	if certBlock == nil {
		return nil, "", fmt.Errorf("failed to decode certificate PEM")
	}
	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Parse the private key
	keyBlock, _ := pem.Decode(key)
	if keyBlock == nil {
		return nil, "", fmt.Errorf("failed to decode key PEM")
	}

	var privateKey interface{}
	var parseErr error

	// Try different key formats
	if keyBlock.Type == "EC PRIVATE KEY" {
		privateKey, parseErr = x509.ParseECPrivateKey(keyBlock.Bytes)
	} else if keyBlock.Type == "RSA PRIVATE KEY" {
		privateKey, parseErr = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	} else {
		// Try PKCS8 as a fallback
		privateKey, parseErr = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	}

	if parseErr != nil {
		return nil, "", fmt.Errorf("failed to parse private key: %v", parseErr)
	}

	// Parse CA certificates if provided
	var caCerts []*x509.Certificate
	if len(ca) > 0 {
		var caPEM *pem.Block
		caPEMData := ca
		for len(caPEMData) > 0 {
			caPEM, caPEMData = pem.Decode(caPEMData)
			if caPEM == nil {
				break
			}
			caCert, err := x509.ParseCertificate(caPEM.Bytes)
			if err != nil {
				l.WithError(err).Warn("Failed to parse CA certificate, skipping")
				continue
			}
			caCerts = append(caCerts, caCert)
		}
	}

	// If no password provided, generate a random one
	if password == "" {
		// Generate a random password
		passwordBytes := make([]byte, 16)
		if _, err := rand.Read(passwordBytes); err != nil {
			return nil, "", fmt.Errorf("failed to generate random password: %v", err)
		}
		password = fmt.Sprintf("%x", passwordBytes)
	}

	// Create PKCS#12 data using the modern encoding for better security
	pfxData, err := pkcs12.Modern.Encode(privateKey, certificate, caCerts, password)
	if err != nil {
		return nil, "", fmt.Errorf("failed to encode PKCS#12: %v", err)
	}

	return pfxData, password, nil
}

// convertToPKCS12 converts PEM certificate and key to PKCS#12 format
func (s *VaultStore) convertToPKCS12(cert []byte, key []byte, ca []byte, c *tlssecret.Certificate) ([]byte, string, error) {
	l := log.WithFields(log.Fields{
		"action": "convertToPKCS12",
	})
	l.Debug("Converting certificate to PKCS#12 format")

	// Try to get password from secret
	password, err := s.getPasswordFromSecret(c)
	if err != nil {
		l.WithError(err).Error("Failed to get password from secret")
		return nil, "", fmt.Errorf("failed to get password from secret: %v", err)
	}

	// Convert to PKCS#12 with the password (or generate a random one if empty)
	return s.convertToPKCS12WithPassword(cert, key, ca, password)
}

func (s *VaultStore) Sync(c *tlssecret.Certificate) (map[string]string, error) {
	l := log.WithFields(log.Fields{
		"action":          "Update",
		"store":           "vault",
		"secretName":      c.SecretName,
		"secretNamespace": c.Namespace,
	})
	l.Debugf("Update")
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

	// If PKCS12 is enabled and we need to use the certificate namespace for the password secret
	if s.PKCS12 && s.PKCS12PassSecret != "" && s.PKCS12PassSecretNamespace == "" {
		// Set the namespace to the certificate namespace
		s.PKCS12PassSecretNamespace = c.Namespace
	}

	_, cerr := s.NewClient()
	if cerr != nil {
		l.WithError(cerr).Errorf("vault.NewClient error")
		return nil, cerr
	}
	_, err := s.NewToken()
	if err != nil {
		l.WithError(err).Errorf("vault.NewToken error")
		return nil, err
	}

	cd := map[string]interface{}{}

	// Always store the original PEM files
	cd["tls.crt"] = writeSecretValue(c.Certificate, s.Base64Decode)
	cd["tls.key"] = writeSecretValue(c.Key, s.Base64Decode)
	if len(c.Ca) > 0 {
		cd["ca.crt"] = writeSecretValue(c.Ca, s.Base64Decode)
	}

	// If PKCS#12 is enabled, convert and store the certificate in PKCS#12 format
	if s.PKCS12 {
		l.Debug("Converting certificate to PKCS#12 format")
		pkcs12Data, password, err := s.convertToPKCS12(c.Certificate, c.Key, c.Ca, c)
		if err != nil {
			l.WithError(err).Errorf("PKCS#12 conversion error")
			return nil, err
		}

		cd["pkcs12"] = writeSecretValue(pkcs12Data, s.Base64Decode)

		// Store the password if it was generated (not provided in secret)
		if s.PKCS12PassSecret == "" {
			cd["pkcs12-password"] = password
		}
	}

	_, err = s.WriteSecret(cd)
	if err != nil {
		l.WithError(err).Errorf("sync error")
		return nil, err
	}
	l.Info("certificate synced")
	return nil, nil
}
