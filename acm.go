package main

import (
	"context"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/acm"
)

// handleK8sCertsForACM handles the sync of all ACM-enabled certs
func handleK8sCertsForACM(ss []corev1.Secret) ([]corev1.Secret, error) {
	ss = SortK8sSecretsForAWSProcessing(ss)
	l := log.WithFields(
		log.Fields{
			"action": "handleK8sCertsForACM",
		},
	)

	l.Print("handleK8sCertsForACM")
	for i, s := range ss {
		if s.ObjectMeta.Annotations[operatorName+"/acm-enabled"] == "true" {
			l.Debugf("processing secret %s (%d/%d)", s.ObjectMeta.Name, i+1, len(ss))
			err := handleACMCert(s)
			if err != nil {
				l.Printf("handleACMCert error=%v", err)
				continue
			}
			c := k8sTLSSecretToTextCert(s)
			addToCache(c)
		}
	}
	return ss, nil
}

// handleACMCert handles the update of a single ACM Certificate
func handleACMCert(s corev1.Secret) error {
	l := log.WithFields(
		log.Fields{
			"action": "handleACMCert",
			"name":   s.ObjectMeta.Name,
		},
	)
	l.Print("handleACMCert")
	ai, err := secretToACMInput(s)
	if err != nil {
		l.Print(err)
		return err
	}

	certArn, cerr := replicateCertToAWS(ai, s)
	if cerr != nil {
		l.Print(cerr)
		return cerr
	}

	s.ObjectMeta.Annotations[operatorName+"/acm-certificate-arn"] = certArn
	sc := k8sClient.CoreV1().Secrets(os.Getenv("SECRETS_NAMESPACE"))
	uo := metav1.UpdateOptions{}

	l.Printf("certArn=%v", certArn)

	_, uerr := sc.Update(
		context.Background(),
		&s,
		uo,
	)

	if uerr != nil {
		l.Print(uerr)
		return uerr
	}

	return nil
}

// separateCertsACM wraps separateCerts and returns an acm ImportCertificateInput Object
func separateCertsACM(name string, ca, crt, key []byte) *acm.ImportCertificateInput {
	cert := separateCerts(name, ca, crt, key)
	im := &acm.ImportCertificateInput{
		CertificateChain: cert.Chain,
		Certificate:      cert.Certificate,
		PrivateKey:       cert.Key,
	}
	return im
}

// secretToACMInput converts a k8s secret to a properly-formatted ACM Import object
func secretToACMInput(s corev1.Secret) (*acm.ImportCertificateInput, error) {
	l := log.WithFields(
		log.Fields{
			"action":     "secretToACMInput",
			"secretName": s.ObjectMeta.Name,
		},
	)

	im := separateCertsACM(s.ObjectMeta.Name, s.Data["ca.crt"], s.Data["tls.crt"], s.Data["tls.key"])

	// secret already has an aws acm cert attached
	if s.ObjectMeta.Annotations[operatorName+"/acm-certificate-arn"] != "" {
		im.CertificateArn = aws.String(s.ObjectMeta.Annotations[operatorName+"/acm-certificate-arn"])
	} else {
		// this is our first time sending to ACM, tag
		var tags []*acm.Tag
		tags = append(tags, &acm.Tag{
			Key:   aws.String(operatorName + "/secret-name"),
			Value: aws.String(s.ObjectMeta.Name),
		})
		im.Tags = tags
	}
	l.Print("secretToACMInput")
	return im, nil
}

// ImportCertificate imports a cert into ACM
func ImportCertificate(s *session.Session, cfg *aws.Config, im *acm.ImportCertificateInput, arn string) (string, error) {
	l := log.WithFields(
		log.Fields{
			"action": "ImportCertificate",
		},
	)
	l.Print("ImportCertificate")
	svc := acm.New(s, cfg)
	if arn != "" {
		im.CertificateArn = &arn
	}
	cert, err := svc.ImportCertificate(im)
	if err != nil {
		l.Printf("awsacm.ImportCertificate svc.ImportCertificate error: %v\n", err)
		return "", err
	}
	return *cert.CertificateArn, nil
}
