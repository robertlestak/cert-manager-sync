package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/acm"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"os"
)

// handleK8sCertsForASM handles the update of a single secret placement into AWS
func handleK8sCertsForASM(ss []corev1.Secret) error {
	ss = SortK8sSecretsForAWSProcessing(ss)

	l := log.WithFields(
		log.Fields{
			"action": "handleK8sCertsForASM",
		},
	)
	l.Print("handleK8sCertsForASM")

	for i, s := range ss {
		roleArn := s.ObjectMeta.Annotations[operatorName+"/aws-role-arn"]
		region := s.ObjectMeta.Annotations[operatorName+"/aws-region"]

		l.Debugf("processing secret %s (%d/%d)", s.ObjectMeta.Name, i+1, len(ss))

		err := handleACMCert(s)
		if err != nil {
			l.Printf("handleACMCert error=%v", err)
			continue
		}

		c := k8sTLSSecretToTextCert(s)
		addToCache(c)

		sess, cfg, serr := CreateAWSSession(roleArn, region)

		if serr != nil {
			l.Printf("CreateAWSSession error=%v", serr)
			return serr
		}

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

		ImportSecrets(sess, cfg, ai, s)

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
	}
	return nil
}

// ImportSecrets imports a cert into SecretsManager
func ImportSecrets(sess *session.Session, cfg *aws.Config, im *acm.ImportCertificateInput, s corev1.Secret) (string, error) {
	secretName := s.ObjectMeta.Annotations[operatorName+"/asm-name"]
	secretDesc := s.ObjectMeta.Annotations[operatorName+"/asm-description"]
	secretObj := s.ObjectMeta.Name

	l := log.WithFields(
		log.Fields{
			"action": "ImportCertificateAsSecret",
		},
	)

	if secretName == "" {
		return "", fmt.Errorf("'asm-name' cannot be nil. Please fix annotation for %s", secretObj)
	}

	l.Print("ImportCertificateAsSecret")
	svc := secretsmanager.New(sess, cfg)

	if im.PrivateKey != nil {
		if secretDesc == "" {
			secretDesc = "Private TLS Key"
		}
		privkeyInput := &secretsmanager.CreateSecretInput{
			Description:  aws.String(secretDesc),
			Name:         aws.String(secretName),
			SecretString: aws.String(string(im.PrivateKey)),
		}

		_, err := svc.CreateSecret(privkeyInput)
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				err = fmt.Errorf("%s", aerr.Error())
				if aerr.Code() != "" {
					err = fmt.Errorf("%s: %s", aerr.Code(), aerr.Error())
				}
			} else {
				// Print the error, cast err to awserr.Error to get the Code and
				// Message from an error.
				err = errors.New(err.Error())
			}
			return "", err
		}
	}

	if im.Certificate != nil {
		if secretDesc == "" {
			secretDesc = "TLS Certificate"
		}
		certInput := &secretsmanager.CreateSecretInput{
			Description:  aws.String(secretDesc),
			Name:         aws.String(secretName),
			SecretString: aws.String(string(im.Certificate)),
		}

		_, err := svc.CreateSecret(certInput)
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				err = fmt.Errorf("%s", aerr.Error())
				if aerr.Code() != "" {
					err = fmt.Errorf("%s: %s", aerr.Code(), aerr.Error())
				}
			} else {
				// Print the error, cast err to awserr.Error to get the Code and
				// Message from an error.
				err = errors.New(err.Error())
			}
			return "", err
		}
	}

	if im.CertificateChain != nil {
		if secretDesc == "" {
			secretDesc = "TLS Certificate Chain"
		}
		certChainInput := &secretsmanager.CreateSecretInput{
			Description:  aws.String(secretDesc),
			Name:         aws.String(secretName),
			SecretString: aws.String(string(im.CertificateChain)),
		}

		_, err := svc.CreateSecret(certChainInput)
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				err = fmt.Errorf("%s", aerr.Error())
				if aerr.Code() != "" {
					err = fmt.Errorf("%s: %s", aerr.Code(), aerr.Error())
				}
			} else {
				// Print the error, cast err to awserr.Error to get the Code and
				// Message from an error.
				err = errors.New(err.Error())
			}
			return "", err
		}
	}

	return "Secrets successfully imported.", nil
}
