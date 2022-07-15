package main

import (
	"context"
	"os"
	"strings"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/acm"
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

// handleACMCerts handles the sync of all ACM-enabled certs
func handleACMCerts(ss []corev1.Secret) {
	ss = ACMCerts(ss)
	l := log.WithFields(
		log.Fields{
			"action": "handleACMCerts",
		},
	)
	l.Print("handleACMCerts")
	for i, s := range ss {
		l.Debugf("processing secret %s (%d/%d)", s.ObjectMeta.Name, i+1, len(ss))
		err := handleACMCert(s)
		if err != nil {
			l.Printf("handleACMCert error=%v", err)
			continue
		}
		c := secretToCert(s)
		addToCache(c)
	}
}

// ACMCerts accepts a slice of Secrets and returns only those configured
// for replication to ACM
func ACMCerts(s []corev1.Secret) []corev1.Secret {
	var ac []corev1.Secret
	for _, v := range s {
		if v.Annotations[operatorName+"/acm-enabled"] == "true" && cacheChanged(v) {
			ac = append(ac, v)
		}
	}
	return ac
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

// replicateACMCert takes an ACM ImportCertificateInput and replicates it to AWS CertificateManager
func replicateACMCert(ai *acm.ImportCertificateInput, roleArn string, region string) (string, error) {
	var arn string
	l := log.WithFields(
		log.Fields{
			"action": "replicateACMCert",
		},
	)
	l.Print("replicateACMCert")
	// inefficient creation of session on each import - can be cached
	sess, cfg, serr := CreateAWSSession(roleArn, region)
	if serr != nil {
		l.Printf("CreateAWSSession error=%v", serr)
		return arn, serr
	}
	c, cerr := ImportCertificate(sess, cfg, ai, "")
	if cerr != nil {
		l.Printf("ImportCertificate error=%v", cerr)
		return arn, cerr
	}
	l.Printf("cert created arn=%v", c)
	return c, nil
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
