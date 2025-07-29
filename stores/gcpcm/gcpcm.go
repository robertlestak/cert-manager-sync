package gcpcm

import (
	"context"
	"fmt"
	"strings"

	certificatemanager "cloud.google.com/go/certificatemanager/apiv1"
	"cloud.google.com/go/certificatemanager/apiv1/certificatemanagerpb"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	log "github.com/sirupsen/logrus"
	certificatemanagerv1 "google.golang.org/api/certificatemanager/v1"
	"google.golang.org/api/option"
	"google.golang.org/genproto/protobuf/field_mask"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type GCPStore struct {
	CertificateName string
	ProjectID       string
	Location        string
	SecretName      string
	SecretNamespace string
	CredentialsJSON string
	// Trust store specific fields
	TrustConfigName string
	OperationType   string // "certificate" (default) or "truststore"
	CertificateType string // "root" or "intermediate" (for trust store operations)
	// unexported
	client     *certificatemanager.Client
	restClient *certificatemanagerv1.Service
}

func (s *GCPStore) GetApiKey(ctx context.Context) error {
	gopt := metav1.GetOptions{}
	sc, err := state.KubeClient.CoreV1().Secrets(s.SecretNamespace).Get(ctx, s.SecretName, gopt)
	if err != nil {
		return err
	}
	if sc.Data["GOOGLE_APPLICATION_CREDENTIALS"] == nil {
		return fmt.Errorf("GOOGLE_APPLICATION_CREDENTIALS not found in secret %s/%s", s.SecretNamespace, s.SecretName)
	}
	s.CredentialsJSON = string(sc.Data["GOOGLE_APPLICATION_CREDENTIALS"])
	return nil
}

// secretToGCPInput converts a k8s secret to a properly-formatted GCP Import object
func (s *GCPStore) certToGCPCert(c *tlssecret.Certificate) *certificatemanagerpb.Certificate {
	fullChain := c.FullChain()
	sm_cert := &certificatemanagerpb.Certificate_SelfManagedCertificate{
		PemCertificate: string(fullChain),
		PemPrivateKey:  string(c.Key),
	}
	if s.CertificateName == "" {
		s.CertificateName = "projects/" + s.ProjectID + "/locations/" + s.Location + "/certificates/" + c.Namespace + "-" + c.SecretName
	}
	return &certificatemanagerpb.Certificate{
		Name: s.CertificateName,
		Type: &certificatemanagerpb.Certificate_SelfManaged{SelfManaged: sm_cert}}
}

func (s *GCPStore) FromConfig(c tlssecret.GenericSecretSyncConfig) error {
	l := log.WithFields(log.Fields{
		"action": "FromConfig",
	})
	l.Debugf("FromConfig")
	if c.Config["project"] != "" {
		s.ProjectID = c.Config["project"]
	}
	if c.Config["location"] != "" {
		s.Location = c.Config["location"]
	}
	if c.Config["certificate-name"] != "" {
		s.CertificateName = c.Config["certificate-name"]
	}
	if c.Config["secret-name"] != "" {
		s.SecretName = c.Config["secret-name"]
	}
	// Trust store specific configuration
	if c.Config["operation-type"] != "" {
		s.OperationType = c.Config["operation-type"]
	} else {
		s.OperationType = "certificate" // default
	}
	if c.Config["trust-config-name"] != "" {
		s.TrustConfigName = c.Config["trust-config-name"]
	}
	if c.Config["certificate-type"] != "" {
		s.CertificateType = c.Config["certificate-type"]
	} else {
		s.CertificateType = "root" // default for trust store operations
	}
	// if secret name is in the format of "namespace/secretname" then parse it
	if strings.Contains(s.SecretName, "/") {
		s.SecretNamespace = strings.Split(s.SecretName, "/")[0]
		s.SecretName = strings.Split(s.SecretName, "/")[1]
	}
	return nil
}

func (s *GCPStore) CreateCert(ctx context.Context, gcert *certificatemanagerpb.Certificate) error {
	l := log.WithFields(log.Fields{
		"action": "CreateCert",
	})
	l.Debugf("CreateCert")
	req := &certificatemanagerpb.CreateCertificateRequest{
		// TODO: Fill request struct fields.
		// See https://pkg.go.dev/google.golang.org/genproto/googleapis/cloud/certificatemanager/v1#CreateCertificateRequest.
		Parent:        "projects/" + s.ProjectID + "/locations/" + s.Location,
		CertificateId: strings.Split(s.CertificateName, "/")[5],
		Certificate:   gcert,
	}
	op, err := s.client.CreateCertificate(ctx, req)
	if err != nil {
		// TODO: Handle error.
		l.Errorf("cannot create cert because of %s", err)
		return err
	}
	resp, err := op.Wait(ctx)
	if err != nil {
		// TODO: Handle error.
		l.Errorf("cannot complete creating cert because of %s", err)
		return err
	}
	l.WithField("name", resp.Name).Debugf("Cert created in GCP as %s", resp.Name)
	s.CertificateName = resp.Name
	return nil
}

func (s *GCPStore) UpdateCert(ctx context.Context, gcert *certificatemanagerpb.Certificate) error {
	l := log.WithFields(log.Fields{
		"action": "UpdateCert",
	})
	l.Debugf("UpdateCert")
	req := &certificatemanagerpb.UpdateCertificateRequest{
		Certificate: gcert,
		UpdateMask: &field_mask.FieldMask{
			Paths: []string{"self_managed"},
		},
	}
	op, err := s.client.UpdateCertificate(ctx, req)
	if err != nil {
		l.Errorf("cannot update cert because of %s", err)
		return err
	}
	resp, err := op.Wait(ctx)
	if err != nil {
		l.Errorf("cannot complete updating cert because of %s", err)
		return err
	}
	l.WithField("name", resp.Name).Debugf("Cert updated in GCP as %s", resp.Name)
	return nil
}

// certToTrustAnchor converts a certificate to a TrustAnchor for trust store
func (s *GCPStore) certToTrustAnchor(c *tlssecret.Certificate) *certificatemanagerv1.TrustAnchor {
	return &certificatemanagerv1.TrustAnchor{
		PemCertificate: string(c.Certificate),
	}
}

// certToIntermediateCA converts a certificate to an IntermediateCA for trust store
func (s *GCPStore) certToIntermediateCA(c *tlssecret.Certificate) *certificatemanagerv1.IntermediateCA {
	return &certificatemanagerv1.IntermediateCA{
		PemCertificate: string(c.Certificate),
	}
}

// createTrustStore creates a TrustStore with the certificate
func (s *GCPStore) createTrustStore(c *tlssecret.Certificate) *certificatemanagerv1.TrustStore {
	trustStore := &certificatemanagerv1.TrustStore{}

	if s.CertificateType == "intermediate" {
		trustStore.IntermediateCas = []*certificatemanagerv1.IntermediateCA{
			s.certToIntermediateCA(c),
		}
	} else {
		// Default to root certificate (TrustAnchor)
		trustStore.TrustAnchors = []*certificatemanagerv1.TrustAnchor{
			s.certToTrustAnchor(c),
		}
	}

	return trustStore
}

// CreateTrustConfig creates a new TrustConfig with trust store
func (s *GCPStore) CreateTrustConfig(ctx context.Context, c *tlssecret.Certificate) error {
	l := log.WithFields(log.Fields{
		"action": "CreateTrustConfig",
	})
	l.Debugf("CreateTrustConfig")

	if s.TrustConfigName == "" {
		s.TrustConfigName = "projects/" + s.ProjectID + "/locations/" + s.Location + "/trustConfigs/" + c.Namespace + "-" + c.SecretName
	}

	trustStore := s.createTrustStore(c)
	trustConfig := &certificatemanagerv1.TrustConfig{
		Name:        s.TrustConfigName,
		TrustStores: []*certificatemanagerv1.TrustStore{trustStore},
	}

	parent := "projects/" + s.ProjectID + "/locations/" + s.Location
	trustConfigId := strings.Split(s.TrustConfigName, "/")[5]

	call := s.restClient.Projects.Locations.TrustConfigs.Create(parent, trustConfig)
	call.TrustConfigId(trustConfigId)

	op, err := call.Do()
	if err != nil {
		l.Errorf("cannot create trust config because of %s", err)
		return err
	}

	l.WithField("name", op.Name).Debugf("TrustConfig created in GCP as %s", op.Name)
	return nil
}

// UpdateTrustConfig updates an existing TrustConfig
func (s *GCPStore) UpdateTrustConfig(ctx context.Context, c *tlssecret.Certificate) error {
	l := log.WithFields(log.Fields{
		"action": "UpdateTrustConfig",
	})
	l.Debugf("UpdateTrustConfig")

	trustStore := s.createTrustStore(c)
	trustConfig := &certificatemanagerv1.TrustConfig{
		Name:        s.TrustConfigName,
		TrustStores: []*certificatemanagerv1.TrustStore{trustStore},
	}

	call := s.restClient.Projects.Locations.TrustConfigs.Patch(s.TrustConfigName, trustConfig)
	call.UpdateMask("trust_stores")

	op, err := call.Do()
	if err != nil {
		l.Errorf("cannot update trust config because of %s", err)
		return err
	}

	l.WithField("name", op.Name).Debugf("TrustConfig updated in GCP as %s", op.Name)
	return nil
}

func (s *GCPStore) Sync(c *tlssecret.Certificate) (map[string]string, error) {
	s.SecretNamespace = c.Namespace
	l := log.WithFields(log.Fields{
		"action":          "Sync",
		"store":           "gcp",
		"secretName":      s.SecretName,
		"secretNamespace": s.SecretNamespace,
		"operationType":   s.OperationType,
	})
	l.Debugf("Update")

	ctx := context.Background()
	var clientOpts []option.ClientOption
	if s.SecretName != "" {
		if err := s.GetApiKey(ctx); err != nil {
			l.WithError(err).Errorf("gcp.GetApiKey error")
			return nil, err
		}
		opt := option.WithCredentialsJSON([]byte(s.CredentialsJSON))
		clientOpts = append(clientOpts, opt)
	}

	// Route to appropriate operation based on type
	if s.OperationType == "truststore" {
		return s.syncTrustStore(ctx, c, clientOpts, l)
	} else {
		return s.syncCertificate(ctx, c, clientOpts, l)
	}
}

// syncCertificate handles regular certificate operations
func (s *GCPStore) syncCertificate(ctx context.Context, c *tlssecret.Certificate, clientOpts []option.ClientOption, l *log.Entry) (map[string]string, error) {
	isNewCert := s.CertificateName == ""
	gcert := s.certToGCPCert(c)

	client, err := certificatemanager.NewClient(ctx, clientOpts...)
	if err != nil {
		l.WithError(err).Errorf("certificatemanager.NewClient error")
		return nil, err
	}
	s.client = client

	l = l.WithFields(log.Fields{
		"id": s.CertificateName,
	})

	var newKeys map[string]string
	// if there is no certificate name before certToGCPCert, this is the first time we are sending to GCP, create
	if isNewCert {
		err = s.CreateCert(ctx, gcert)
		if err != nil {
			l.WithError(err).Errorf("CreateCert error")
			return nil, err
		}
		// update secret with new cert name
		newKeys = map[string]string{
			"certificate-name": s.CertificateName,
		}
	} else {
		// secret already has an GCP cert attached, update
		err = s.UpdateCert(ctx, gcert)
		if err != nil {
			l.WithError(err).Errorf("UpdateCert error")
			return nil, err
		}
	}
	l.Info("certificate synced")
	return newKeys, nil
}

// syncTrustStore handles trust store operations
func (s *GCPStore) syncTrustStore(ctx context.Context, c *tlssecret.Certificate, clientOpts []option.ClientOption, l *log.Entry) (map[string]string, error) {
	isNewTrustConfig := s.TrustConfigName == ""

	// Create REST API client for TrustConfig operations
	restClient, err := certificatemanagerv1.NewService(ctx, clientOpts...)
	if err != nil {
		l.WithError(err).Errorf("certificatemanagerv1.NewService error")
		return nil, err
	}
	s.restClient = restClient

	l = l.WithFields(log.Fields{
		"trustConfigName": s.TrustConfigName,
		"certificateType": s.CertificateType,
	})

	var newKeys map[string]string
	if isNewTrustConfig {
		err = s.CreateTrustConfig(ctx, c)
		if err != nil {
			l.WithError(err).Errorf("CreateTrustConfig error")
			return nil, err
		}
		// update secret with new trust config name
		newKeys = map[string]string{
			"trust-config-name": s.TrustConfigName,
		}
	} else {
		// trust config already exists, update it
		err = s.UpdateTrustConfig(ctx, c)
		if err != nil {
			l.WithError(err).Errorf("UpdateTrustConfig error")
			return nil, err
		}
	}
	l.Info("trust store synced")
	return newKeys, nil
}
