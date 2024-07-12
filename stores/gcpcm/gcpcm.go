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
	"google.golang.org/api/option"
	"google.golang.org/genproto/protobuf/field_mask"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type GCPStore struct {
	CertificateName string
	ProjectID       string
	Location        string
	SecretName      string
	SecretNamespace string
	CredentialsJSON string
	// unexported
	client *certificatemanager.Client
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
func (s *GCPStore) secretToGCPCert(secret *corev1.Secret) *certificatemanagerpb.Certificate {
	fullChain := tlssecret.ParseSecret(secret).FullChain()
	sm_cert := &certificatemanagerpb.Certificate_SelfManagedCertificate{
		PemCertificate: string(fullChain),
		PemPrivateKey:  string(secret.Data["tls.key"]),
	}
	if s.CertificateName == "" {
		s.CertificateName = "projects/" + s.ProjectID + "/locations/" + s.Location + "/certificates/" + secret.ObjectMeta.Namespace + "-" + secret.ObjectMeta.Name
	}
	return &certificatemanagerpb.Certificate{
		Name: s.CertificateName,
		Type: &certificatemanagerpb.Certificate_SelfManaged{SelfManaged: sm_cert}}
}

func (s *GCPStore) ParseCertificate(c *tlssecret.Certificate) error {
	l := log.WithFields(log.Fields{
		"action": "ParseCertificate",
	})
	l.Debugf("ParseCertificate")
	if c.Annotations[state.OperatorName+"/gcp-project"] != "" {
		s.ProjectID = c.Annotations[state.OperatorName+"/gcp-project"]
	}
	if c.Annotations[state.OperatorName+"/gcp-location"] != "" {
		s.Location = c.Annotations[state.OperatorName+"/gcp-location"]
	}
	if c.Annotations[state.OperatorName+"/gcp-certificate-name"] != "" {
		s.CertificateName = c.Annotations[state.OperatorName+"/gcp-certificate-name"]
	}
	if c.Annotations[state.OperatorName+"/gcp-secret-name"] != "" {
		s.SecretName = c.Annotations[state.OperatorName+"/gcp-secret-name"]
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

func (s *GCPStore) Update(secret *corev1.Secret) error {
	l := log.WithFields(log.Fields{
		"action":          "Update",
		"store":           "gcp",
		"secretName":      secret.ObjectMeta.Name,
		"secretNamespace": secret.ObjectMeta.Namespace,
	})
	l.Debugf("Update")
	c := tlssecret.ParseSecret(secret)
	if err := s.ParseCertificate(c); err != nil {
		l.WithError(err).Errorf("vault.ParseCertificate error")
		return err
	}
	gcert := s.secretToGCPCert(secret)
	ctx := context.Background()
	var clientOpts []option.ClientOption
	if s.SecretName != "" {
		if err := s.GetApiKey(ctx); err != nil {
			l.WithError(err).Errorf("gcp.GetApiKey error")
			return err
		}
		opt := option.WithCredentialsJSON([]byte(s.CredentialsJSON))
		clientOpts = append(clientOpts, opt)
	}
	client, err := certificatemanager.NewClient(ctx, clientOpts...)
	if err != nil {
		l.WithError(err).Errorf("certificatemanager.NewClient error")
		return err
	}
	s.client = client
	// if there is no secret name, this is the first time we are sending to GCP, create
	if secret.ObjectMeta.Annotations[state.OperatorName+"/gcp-certificate-name"] == "" {
		err = s.CreateCert(ctx, gcert)
		if err != nil {
			l.WithError(err).Errorf("vault.WriteSecret error")
			return err
		}
		// update secret with new cert name
		secret.ObjectMeta.Annotations[state.OperatorName+"/gcp-certificate-name"] = s.CertificateName
		sc := state.KubeClient.CoreV1().Secrets(secret.ObjectMeta.Namespace)
		uo := metav1.UpdateOptions{}
		_, uerr := sc.Update(
			context.Background(),
			secret,
			uo,
		)
		if uerr != nil {
			l.WithError(uerr).Errorf("secret.Update error")
			return uerr
		}
	} else {
		// secret already has an GCP cert attached, update
		err = s.UpdateCert(ctx, gcert)
		if err != nil {
			l.WithError(err).Errorf("vault.WriteSecret error")
			return err
		}
	}
	l.WithFields(log.Fields{
		"certificateName": s.CertificateName,
	}).Info("certificate synced")
	return nil
}
