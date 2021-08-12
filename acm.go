package main

import (
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/acm"
)

// CreateAWSSession will connect to AWS with the account's credentials from vault
func CreateAWSSession() (*session.Session, error) {
	l := log.WithFields(
		log.Fields{
			"action": "CreateAWSSession",
		},
	)
	l.Print("CreateAWSSession")
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(os.Getenv("AWS_REGION"))},
	)
	if err != nil {
		l.Printf("%+v", err)
	}
	return sess, nil
}

// separateCerts ensures that certificates are configured appropriately
func separateCerts(name string, ca, crt, key []byte) *Certificate {
	b := "-----BEGIN CERTIFICATE-----\n"
	str := strings.Split(string(crt), b)
	nc := b + str[1]
	ch := strings.Join(str[:len(str)-1], b)
	cert := &Certificate{
		SecretName:  name,
		Chain:       []byte(ch),
		Certificate: []byte(nc),
		Key:         key,
	}
	return cert
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

// ImportCertificate imports a cert into ACM
func ImportCertificate(s *session.Session, im *acm.ImportCertificateInput, arn string) (string, error) {
	l := log.WithFields(
		log.Fields{
			"action": "ImportCertificate",
		},
	)
	l.Print("ImportCertificate")
	svc := acm.New(s)
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
