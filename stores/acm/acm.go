package acm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/acm"
	"github.com/google/uuid"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ACMStore struct {
	Region          string
	RoleArn         string
	CertificateArn  string
	SecretName      string
	SecretNamespace string
	AccessKeyId     string
	SecretAccessKey string
}

func (s *ACMStore) GetApiKey(ctx context.Context) error {
	gopt := metav1.GetOptions{}
	sc, err := state.KubeClient.CoreV1().Secrets(s.SecretNamespace).Get(ctx, s.SecretName, gopt)
	if err != nil {
		return fmt.Errorf("failed to get AWS credentials secret %s/%s: %w", s.SecretNamespace, s.SecretName, err)
	}
	if sc.Data["AWS_ACCESS_KEY_ID"] == nil {
		return fmt.Errorf("AWS_ACCESS_KEY_ID not found in secret %s/%s", s.SecretNamespace, s.SecretName)
	}
	if sc.Data["AWS_SECRET_ACCESS_KEY"] == nil {
		return fmt.Errorf("AWS_SECRET_ACCESS_KEY not found in secret %s/%s", s.SecretNamespace, s.SecretName)
	}
	s.AccessKeyId = string(sc.Data["AWS_ACCESS_KEY_ID"])
	s.SecretAccessKey = string(sc.Data["AWS_SECRET_ACCESS_KEY"])
	return nil
}

func (s *ACMStore) awsRegion() string {
	if s.Region == "" {
		s.Region = os.Getenv("AWS_REGION")
	}
	if s.Region == "" {
		s.Region = "us-east-1"
	}
	return s.Region
}

// createAWSSession will connect to AWS with the account's credentials from vault
func (s *ACMStore) createAWSSession() (*session.Session, *aws.Config, error) {
	l := log.WithFields(
		log.Fields{
			"action": "createAWSSession",
		},
	)
	l.Debug("createAWSSession")
	cfg := &aws.Config{
		Region: aws.String(s.awsRegion()),
	}
	if s.SecretName != "" {
		if err := s.GetApiKey(context.Background()); err != nil {
			l.Debugf("GetApiKey error=%v", err)
			return nil, nil, err
		}
		cfg.Credentials = credentials.NewStaticCredentials(s.AccessKeyId, s.SecretAccessKey, "")
	}
	sess, err := session.NewSession(cfg)
	reqId := uuid.New().String()
	if s.RoleArn != "" {
		l.Debugf("createAWSSession roleArn=%s requestId=%s", s.RoleArn, reqId)
		creds := stscreds.NewCredentials(sess, s.RoleArn, func(p *stscreds.AssumeRoleProvider) {
			p.RoleSessionName = "cert-manager-sync-" + reqId
		})
		cfg.Credentials = creds
	}
	if err != nil {
		l.Debugf("%+v", err)
	}
	return sess, cfg, nil
}

// importCertificate imports a cert into ACM
func (s *ACMStore) importCertificate(sess *session.Session, cfg *aws.Config, im *acm.ImportCertificateInput) error {
	l := log.WithFields(
		log.Fields{
			"action": "importCertificate",
		},
	)
	l.Debug("importCertificate")
	svc := acm.New(sess, cfg)
	if s.CertificateArn != "" {
		im.CertificateArn = aws.String(s.CertificateArn)
	}
	cert, err := svc.ImportCertificate(im)
	if err != nil {
		l.Debugf("awsacm.importCertificate svc.importCertificate error: %v\n", err)
		return fmt.Errorf("failed to import certificate to ACM (region: %s, arn: %s): %w", s.awsRegion(), s.CertificateArn, err)
	}
	l.Debugf("awsacm.importCertificate svc.importCertificate success: %v\n", cert)
	s.CertificateArn = *cert.CertificateArn
	return nil
}

// replicateACMCert takes an ACM ImportCertificateInput and replicates it to AWS CertificateManager
func (s *ACMStore) replicateACMCert(ai *acm.ImportCertificateInput) error {
	l := log.WithFields(
		log.Fields{
			"action": "replicateACMCert",
		},
	)
	l.Debug("replicateACMCert")
	// inefficient creation of session on each import - can be cached
	sess, cfg, serr := s.createAWSSession()
	if serr != nil {
		l.Debugf("createAWSSession error=%v", serr)
		return serr
	}
	cerr := s.importCertificate(sess, cfg, ai)
	if cerr != nil {
		l.Debugf("ImportCertificate error=%v", cerr)
		return cerr
	}
	return nil
}

// separateCertsACM wraps separateCerts and returns an acm ImportCertificateInput Object
func separateCertsACM(ca, crt, key []byte) *acm.ImportCertificateInput {
	re := regexp.MustCompile(`(?s)(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)`)
	certBlocks := re.FindAllString(string(crt), -1)
	if len(certBlocks) == 0 {
		return nil
	}
	nc := certBlocks[0]
	ch := strings.Join(certBlocks[1:], "\n")
	if len(ca) > 0 {
		ch += "\n" + string(ca)
	}
	im := &acm.ImportCertificateInput{
		CertificateChain: []byte(ch),
		Certificate:      []byte(nc),
		PrivateKey:       key,
	}
	return im
}

func (s *ACMStore) certToACMInput(c *tlssecret.Certificate) (*acm.ImportCertificateInput, error) {
	l := log.WithFields(
		log.Fields{
			"action":     "certToACMInput",
			"secretName": c.SecretName,
		},
	)
	im := separateCertsACM(c.Ca, c.Certificate, c.Key)
	if s.CertificateArn == "" {
		// this is our first time sending to ACM, tag
		var tags []*acm.Tag
		secretTagName := c.SecretName
		if c.Namespace != "" {
			secretTagName = c.Namespace + "/" + c.SecretName
		}
		tags = append(tags, &acm.Tag{
			Key:   aws.String(state.OperatorName + "/secret-name"),
			Value: aws.String(secretTagName),
		})
		im.Tags = tags
	}
	l.Debug("secretToACMInput")
	return im, nil
}

func (s *ACMStore) FromConfig(c tlssecret.GenericSecretSyncConfig) error {
	l := log.WithFields(log.Fields{
		"action": "FromConfig",
	})
	l.Debugf("FromConfig")
	if c.Config["role-arn"] != "" {
		s.RoleArn = c.Config["role-arn"]
	}
	if c.Config["region"] != "" {
		s.Region = c.Config["region"]
	}
	if c.Config["certificate-arn"] != "" {
		s.CertificateArn = c.Config["certificate-arn"]
	}
	if c.Config["secret-name"] != "" {
		s.SecretName = c.Config["secret-name"]
	}
	if c.Config["secret-namespace"] != "" {
		s.SecretNamespace = c.Config["secret-namespace"]
	}
	if strings.Contains(s.SecretName, "/") {
		s.SecretNamespace = strings.Split(s.SecretName, "/")[0]
		s.SecretName = strings.Split(s.SecretName, "/")[1]
	}
	return nil
}

// isACMNotFound returns true when the AWS error code indicates the resource is missing.
func isACMNotFound(err error) bool {
	if err == nil {
		return false
	}
	var ae awserr.Error
	if errors.As(err, &ae) {
		return ae.Code() == acm.ErrCodeResourceNotFoundException
	}
	return false
}

// Delete removes the certificate from ACM. ResourceNotFoundException is treated
// as success so the operation is idempotent.
func (s *ACMStore) Delete(_ context.Context) error {
	l := log.WithFields(log.Fields{
		"action": "acm.Delete",
		"arn":    s.CertificateArn,
	})
	if s.CertificateArn == "" {
		// Sync never populated the ARN, so there is no remote certificate
		// to clean up. Treat as success so opt-in secrets that failed their
		// initial sync are not wedged on deletion.
		l.Debug("no acm certificate-arn recorded; nothing to delete")
		return nil
	}
	sess, cfg, err := s.createAWSSession()
	if err != nil {
		return fmt.Errorf("acm session: %w", err)
	}
	svc := acm.New(sess, cfg)
	if _, err := svc.DeleteCertificate(&acm.DeleteCertificateInput{
		CertificateArn: aws.String(s.CertificateArn),
	}); err != nil {
		if isACMNotFound(err) {
			l.Debug("acm certificate already absent; treating delete as success")
			return nil
		}
		return fmt.Errorf("delete ACM certificate %s: %w", s.CertificateArn, err)
	}
	l.Info("certificate deleted from ACM")
	return nil
}

func (s *ACMStore) Sync(c *tlssecret.Certificate) (map[string]string, error) {
	s.SecretNamespace = c.Namespace
	l := log.WithFields(log.Fields{
		"action":     "Sync",
		"secretName": c.SecretName,
	})
	l.Debugf("Sync")
	origArn := s.CertificateArn
	im, err := s.certToACMInput(c)
	if err != nil {
		l.WithError(err).Errorf("certToACMInput error")
		return nil, err
	}
	cerr := s.replicateACMCert(im)
	if cerr != nil {
		l.WithError(cerr).Errorf("replicateACMCert error")
		return nil, cerr
	}
	l = l.WithFields(log.Fields{
		"id": s.CertificateArn,
	})
	var keyUpdates map[string]string
	if origArn != s.CertificateArn {
		keyUpdates = map[string]string{
			"certificate-arn": s.CertificateArn,
		}
	}
	l.Info("certificate synced")
	return keyUpdates, nil
}
