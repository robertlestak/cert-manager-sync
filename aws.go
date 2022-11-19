package main

import (
	"github.com/aws/aws-sdk-go/service/acm"
	corev1 "k8s.io/api/core/v1"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

// CreateAWSSession will connect to AWS with the account's credentials from vault
func CreateAWSSession(roleArn string, region string) (*session.Session, *aws.Config, error) {
	l := log.WithFields(
		log.Fields{
			"action": "CreateAWSSession",
		},
	)
	l.Print("CreateAWSSession")
	if region == "" {
		region = os.Getenv("AWS_REGION")
	}
	if region == "" {
		region = "us-east-1"
	}
	cfg := &aws.Config{
		Region: aws.String(region),
	}
	sess, err := session.NewSession(cfg)
	reqId := uuid.New().String()
	if roleArn != "" {
		l.Printf("CreateAWSSession roleArn=%s requestId=%s", roleArn, reqId)
		creds := stscreds.NewCredentials(sess, roleArn, func(p *stscreds.AssumeRoleProvider) {
			p.RoleSessionName = "cert-manager-sync-" + reqId
		})
		cfg.Credentials = creds
	}
	if err != nil {
		l.Printf("%+v", err)
	}
	return sess, cfg, nil
}

// replicateCertToAWS takes an ACM ImportCertificateInput and replicates it to AWS CertificateManager
func replicateCertToAWS(ai *acm.ImportCertificateInput, s corev1.Secret) (string, error) {
	var arn, c string

	roleArn := s.ObjectMeta.Annotations[operatorName+"/assume-role-arn"]
	region := s.ObjectMeta.Annotations[operatorName+"/aws-region"]
	acm_en := s.ObjectMeta.Annotations[operatorName+"/acm-enabled"]
	asm_en := s.ObjectMeta.Annotations[operatorName+"/asm-enabled"]

	l := log.WithFields(
		log.Fields{
			"action": "replicateCertToAWS",
		},
	)
	l.Print("replicateCertToAWS")

	// inefficient creation of session on each import - can be cached
	sess, cfg, serr := CreateAWSSession(roleArn, region)
	if serr != nil {
		l.Printf("CreateAWSSession error=%v", serr)
		return arn, serr
	}

	if acm_en != "" && acm_en == "true" {
		c, cerr := ImportCertificate(sess, cfg, ai, "")
		if cerr != nil {
			l.Printf("ImportCertificate error=%v", cerr)
			return arn, cerr
		}

		l.Printf("cert created arn=%v", c)
	}

	if asm_en != "" && asm_en == "true" {
		c, cerr := ImportSecrets(sess, cfg, ai, s)
		if cerr != nil {
			l.Printf("ImportCertificate error=%v", cerr)
			return arn, cerr
		}

		l.Printf("cert created arn=%v", c)
	}

	return c, nil
}
