package main

import (
	"context"
	"os"

	log "github.com/sirupsen/logrus"
	"google.golang.org/genproto/protobuf/field_mask"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	// "cloud.google.com/go"
	certificatemanager "cloud.google.com/go/certificatemanager/apiv1"
	certificatemanagerpb "cloud.google.com/go/certificatemanager/apiv1/certificatemanagerpb"
)

// CreateGCPSession will connect to GCP with the account's credentials
func CreateGCPSession(roleArn string, region string){
	l := log.WithFields(
		log.Fields{
			"action": "CreateGCPSession",
		},
	)
	l.Print("CreateGCPSession")
	if region == "" {
		region = os.Getenv("GCP_REGION")
	}
	if region == "" {
		region = "us-central1"
	}
	// cfg := &GCP.Config{
	// 	Region: GCP.String(region),
	// }
	// sess, err := session.NewSession(cfg)
	// reqId := uuid.New().String()
	// if roleArn != "" {
	// 	l.Printf("CreateGCPSession roleArn=%s requestId=%s", roleArn, reqId)
	// 	creds := stscreds.NewCredentials(sess, roleArn, func(p *stscreds.AssumeRoleProvider) {
	// 		p.RoleSessionName = "cert-manager-sync-" + reqId
	// 	})
	// 	cfg.Credentials = creds
	// }
	// if err != nil {
	// 	l.Printf("%+v", err)
	// }
	// return sess, cfg, nil
}




// GCPCerts accepts a slice of Secrets and returns only those configured
// for replication to GCP
func GCPCerts(s []corev1.Secret) []corev1.Secret {
	var ac []corev1.Secret
	for _, v := range s {
		if v.Annotations[operatorName+"/GCP-enabled"] == "true" && cacheChanged(v) {
			ac = append(ac, v)
		}
	}
	return ac
}

// secretToGCPInput converts a k8s secret to a properly-formatted GCP Import object
func secretToGCPCert(s corev1.Secret, project string, location string, gcp_cert_name string) (*certificatemanagerpb.Certificate, error) {


	sm_cert := &certificatemanagerpb.Certificate_SelfManagedCertificate{
		PemCertificate: string(s.Data["tls.crt"]),
		PemPrivateKey: string(s.Data["tls.key"]),
	}


	if gcp_cert_name =="" {
		gcp_cert_name = "projects/"+project+"/locations/" + location + "certificates/" + s.ObjectMeta.Namespace+"-" + s.ObjectMeta.Name
	}

	return &certificatemanagerpb.Certificate{
			Name: gcp_cert_name,
			Type: &certificatemanagerpb.Certificate_SelfManaged{SelfManaged: sm_cert},}, nil


}

// handleGCPCerts handles the sync of all GCP-enabled certs
func handleGCPCerts(ss []corev1.Secret) {
	ss = GCPCerts(ss)
	l := log.WithFields(
		log.Fields{
			"action": "handleGCPCerts",
		},
	)
	l.Print("handleGCPCerts")
	l.Print("connecting to gcp")
	ctx := context.Background()
	// This snippet has been automatically generated and should be regarded as a code template only.
	// It will require modifications to work:
	// - It may require correct/in-range values for request initialization.
	// - It may require specifying regional endpoints when creating the service client as shown in:
	//   https://pkg.go.dev/cloud.google.com/go#hdr-Client_Options
	c, err := certificatemanager.NewClient(ctx)
	if err != nil {
		l.Print(err)
	}
	defer c.Close()
	for i, s := range ss {
		l.Debugf("processing secret %s (%d/%d)", s.ObjectMeta.Name, i+1, len(ss))
		err := handleGCPCert(s,c,ctx)
		if err != nil {
			l.Printf("handleGCPCert error=%v", err)
			continue
		}
		c := secretToCert(s)
		addToCache(c)
	}
}

// handleGCPCert handles the update of a single GCP Certificate
func handleGCPCert(s corev1.Secret, c *certificatemanager.Client, ctx context.Context) error {
	l := log.WithFields(
		log.Fields{
			"action": "handleGCPCert",
			"name":   s.ObjectMeta.Name,
		},
	)
	l.Print("handleGCPCert")
	var project, location string
	if s.ObjectMeta.Annotations[operatorName+"/GCP-project"] != "" {
		project = s.ObjectMeta.Annotations[operatorName+"/GCP-project"]
	} else {
		project = os.Getenv("PROJECT_ID")
	}

	if s.ObjectMeta.Annotations[operatorName+"/GCP-location"] != "" {
		location = s.ObjectMeta.Annotations[operatorName+"/GCP-location"]
	} else {
		location = os.Getenv("LOCATION")
	}
	ai, err := secretToGCPCert(s,project,location,s.ObjectMeta.Annotations[operatorName+"/GCP-certificate-name"])
	if err != nil {
		l.Print(err)
		return err
	}

	
	
	// secret already has an GCP GCP cert attached
	if s.ObjectMeta.Annotations[operatorName+"/GCP-certificate-name"] != "" {
		// this is our first time sending to GCP, tag
			req := &certificatemanagerpb.UpdateCertificateRequest{
				Certificate: ai,
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"self_managed"},
				},
			}
			op, err := c.UpdateCertificate(ctx,req)
			if err != nil {
				// TODO: Handle error.
				l.Errorf("cannot update cert because of %s",err)
				return err
			}
			resp, err := op.Wait(ctx)
			if err != nil {
				// TODO: Handle error.
				l.Errorf("cannot complete updating cert because of %s",err)
				return err
			}
			l.Print(resp)
			l.Infof("Cert updated to CCM as %s", resp.Name)
		} else {
			req := &certificatemanagerpb.CreateCertificateRequest{
				// TODO: Fill request struct fields.
				// See https://pkg.go.dev/google.golang.org/genproto/googleapis/cloud/certificatemanager/v1#CreateCertificateRequest.
				Parent: "projects/"+project+"/locations/" + location,
				CertificateId: s.ObjectMeta.Namespace+"-" + s.ObjectMeta.Name,
				Certificate: ai,}
			op, err := c.CreateCertificate(ctx, req)
				if err != nil {
					// TODO: Handle error.
					l.Errorf("cannot create cert because of %s",err)
					return err
				}
			resp, err := op.Wait(ctx)
				if err != nil {
					// TODO: Handle error.
					l.Errorf("cannot complete creating cert because of %s",err)
					return err
				}
			l.Print(resp)
			s.ObjectMeta.Annotations[operatorName+"/GCP-certificate-name"] = resp.Name
			l.Infof("Cert uploaded to CCM as %s", resp.Name)
	}
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
