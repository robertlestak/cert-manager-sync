package main

import (
	"strings"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)


// handleS3Certs handles the sync of all ACM-enabled certs
func handleS3Certs(ss []corev1.Secret) {
	ss = S3Certs(ss) // filter
	l := log.WithFields(
		log.Fields{
			"action": "handleS3s",
		},
	)
	l.Print("handleS3s")
	for i, s := range ss {
		l.Debugf("processing secret %s (%d/%d)", s.ObjectMeta.Name, i+1, len(ss))
		c := secretToCert(s)
		if c == nil {
			l.Errorf("secretToCert(%s) error: cert required", s.ObjectMeta.Name)
			continue
		}

		roleArn := s.ObjectMeta.Annotations[operatorName+"/s3-role-arn"]
		region := s.ObjectMeta.Annotations[operatorName+"/s3-region"]
		bucket := s.ObjectMeta.Annotations[operatorName+"/s3-bucket"]
		prefix := s.ObjectMeta.Namespace + "/" + s.ObjectMeta.Name
		sess, _, serr := CreateAWSSession(roleArn, region)
		if serr != nil {
			l.Printf("Used roleArn to create AWS session %v", roleArn)
			l.Printf("CreateAWSSession error=%v", serr)
			continue
		}
	
		kvs := map[string]string{
				prefix + "/ca.crt": 	string(c.Chain), 
				prefix + "/tls.crt": 	string(c.Certificate),
				prefix + "/tls.key": 	string(c.Key),
			}
		for k, v := range kvs {
			uploader := s3manager.NewUploader(sess)
			reader := strings.NewReader(v)
			_, serr = uploader.Upload(&s3manager.UploadInput{
				Bucket: aws.String(bucket),
				Key: aws.String(k),
				Body: reader,
			})
			if serr != nil {
				l.Printf("Upload to S3 error=%v", serr)
				continue
			}
		}
		addToCache(c)
	}
}

// S3Certs accepts a slice of Secrets and returns only those configured
// for replication to S3 bucket
func S3Certs(s []corev1.Secret) []corev1.Secret {
	var ac []corev1.Secret
	for _, v := range s {
		if v.Annotations[operatorName+"/s3-enabled"] == "true" && cacheChanged(v) {
			ac = append(ac, v)
		}
	}
	return ac
}
