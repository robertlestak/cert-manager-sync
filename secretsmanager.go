package main

import (
	"context"
	"errors"
	"os"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/acm"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

// ImportSecrets imports a cert into SecretsManager
func ImportSecrets(s *session.Session, cfg *aws.Config, im *acm.ImportCertificateInput, arn string) (string, error) {
	l := log.WithFields(
		log.Fields{
			"action": "ImportCertificateAsSecret",
		},
	)
	l.Print("ImportCertificateAsSecret")
	svc := secretsmanager.New(s, cfg)

	if arn != "" {
		im.CertificateArn = &arn
	}

	cert, err := svc.ImportCertificate(im)

	if err != nil {
		l.Printf("awsSecretsManager.ImportCertificateAsSecret svc.ImportCertificate error: %v\n", err)
		return "", err
	}

	input := &secretsmanager.CreateSecretInput{
		Description:  aws.String("place description string here"),
		Name:         aws.String("name of type of secret here - certificate"),
		SecretString: aws.String(cert),
	}

	result, err := svc.CreateSecret(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			if ok, err := aerr.Code(); ok {
				err = errors.New(aerr.Code(), aerr.Error())
			} else {
				err = errors.New(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			err = errors.New(err.Error())
		}
		return "", err
	}

	input = &secretsmanager.CreateSecretInput{
		Description:  aws.String("place description string here"),
		Name:         aws.String("name of type of secret here -- private cert"),
		SecretString: aws.String(im),
	}

	result, err = svc.CreateSecret(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			if ok, err := aerr.Code(); ok {
				err = errors.New(aerr.Code(), aerr.Error())
			} else {
				err = errors.New(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			err = errors.New(err.Error())
		}
		return "", err
	}

	return *cert.CertificateArn, nil
}

// ASMCerts accepts a slice of k8s Secrets and returns only those configured
// for replication to SecretsManager
func ASMCerts(s []corev1.Secret) []corev1.Secret {
	var ac []corev1.Secret
	for _, v := range s {
		if v.Annotations[operatorName+"/asm-enabled"] == "true" && cacheChanged(v) {
			ac = append(ac, v)
		}
	}
	return ac
}

// handleSecretData handles the update of a single secret placement into AWS
func handleSecretData(s corev1.Secret) error {
	l := log.WithFields(
		log.Fields{
			"action": "handleSecretData",
			"name":   s.ObjectMeta.Name,
		},
	)
	l.Print("handleSecretData")
	ai, err := secretToACMInput(s)
	if err != nil {
		l.Print(err)
		return err
	}
	roleArn := s.ObjectMeta.Annotations[operatorName+"/acm-role-arn"]
	region := s.ObjectMeta.Annotations[operatorName+"/acm-region"]
	certArn, cerr := replicateACMCert(ai, roleArn, region)
	if cerr != nil {
		l.Print(cerr)
		return cerr
	}
	s.ObjectMeta.Annotations[operatorName+"/acm-certificate-arn"] = certArn
	l.Printf("certArn=%v", certArn)
	sc := k8sClient.CoreV1().Secrets(os.Getenv("SECRETS_NAMESPACE"))
	uo := metav1.UpdateOptions{}
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
