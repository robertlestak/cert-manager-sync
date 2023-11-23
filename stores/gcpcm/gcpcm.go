package gcpcm

import (
	"context"

	certificatemanager "cloud.google.com/go/certificatemanager/apiv1"
	"cloud.google.com/go/certificatemanager/apiv1/certificatemanagerpb"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	log "github.com/sirupsen/logrus"
	"google.golang.org/genproto/protobuf/field_mask"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type GCPStore struct {
	CertificateName string
	ProjectID       string
	Location        string

	// unexported
	client *certificatemanager.Client
}

// secretToGCPInput converts a k8s secret to a properly-formatted GCP Import object
func (s *GCPStore) secretToGCPCert(secret *corev1.Secret) *certificatemanagerpb.Certificate {
	sm_cert := &certificatemanagerpb.Certificate_SelfManagedCertificate{
		PemCertificate: string(secret.Data["tls.crt"]),
		PemPrivateKey:  string(secret.Data["tls.key"]),
	}
	if s.CertificateName == "" {
		s.CertificateName = "projects/" + s.ProjectID + "/locations/" + s.Location + "certificates/" + secret.ObjectMeta.Namespace + "-" + secret.ObjectMeta.Name
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
		CertificateId: s.CertificateName,
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
	ctx := context.Background()
	client, err := certificatemanager.NewClient(ctx)
	if err != nil {
		l.WithError(err).Errorf("certificatemanager.NewClient error")
		return err
	}
	s.client = client
	c := tlssecret.ParseSecret(secret)
	if err := s.ParseCertificate(c); err != nil {
		l.WithError(err).Errorf("vault.ParseCertificate error")
		return err
	}
	gcert := s.secretToGCPCert(secret)
	// if there is no secret name, this is the first time we are sending to GCP, create
	if s.CertificateName == "" {
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
