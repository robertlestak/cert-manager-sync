package main

import (
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
