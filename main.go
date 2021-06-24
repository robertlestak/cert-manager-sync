package main

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/acm"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

var (
	// k8sClient contains the kubernetes API client
	k8sClient *kubernetes.Clientset
)

// Certificate represents a properly formatted TLS certificate
type Certificate struct {
	Chain       []byte
	Certificate []byte
	Key         []byte
}

// createKubeClient creates a global k8s client
func createKubeClient() error {
	l := log.WithFields(
		log.Fields{
			"action": "createKubeClient",
		},
	)
	l.Print("get createKubeClient")
	var kubeconfig string
	var err error
	if os.Getenv("KUBECONFIG") != "" {
		kubeconfig = os.Getenv("KUBECONFIG")
	} else if home := homedir.HomeDir(); home != "" {
		kubeconfig = filepath.Join(home, ".kube", "config")
	}
	var config *rest.Config
	// naïvely assume if no kubeconfig file that we are running in cluster
	if _, err := os.Stat(kubeconfig); os.IsNotExist(err) {
		config, err = rest.InClusterConfig()
		if err != nil {
			l.Printf("res.InClusterConfig error=%v", err)
			return err
		}
	} else {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			l.Printf("clientcmd.BuildConfigFromFlags error=%v", err)
			return err
		}
	}
	k8sClient, err = kubernetes.NewForConfig(config)
	if err != nil {
		l.Printf("kubernetes.NewForConfig error=%v", err)
		return err
	}
	return nil
}

// getSecrets returns all sync-enabled secrets managed by the cert-manager-sync operator
func getSecrets() ([]corev1.Secret, error) {
	var slo []corev1.Secret
	var err error
	l := log.WithFields(
		log.Fields{
			"action": "getSecrets",
		},
	)
	l.Print("get secrets")
	sc := k8sClient.CoreV1().Secrets(os.Getenv("SECRETS_NAMESPACE"))
	lo := &metav1.ListOptions{}
	sl, jerr := sc.List(context.Background(), *lo)
	if jerr != nil {
		l.Printf("list error=%v", jerr)
		return slo, jerr
	}
	l.Printf("range secrets: %d", len(sl.Items))
	for _, s := range sl.Items {
		if len(s.Data["tls.crt"]) == 0 || len(s.Data["tls.key"]) == 0 {
			continue
		}
		if s.Annotations["cert-manager-sync.lestak.sh/sync-enabled"] == "true" {
			l.Printf("cert secret: %s", s.ObjectMeta.Name)
			slo = append(slo, s)
		}
	}
	return slo, err
}

// ACMCerts accepts a slice of Secrets and returns only those configured
// for replication to ACM
func ACMCerts(s []corev1.Secret) []corev1.Secret {
	var ac []corev1.Secret
	for _, v := range s {
		if v.Annotations["cert-manager-sync.lestak.sh/enabled"] == "true" {
			ac = append(ac, v)
		}
	}
	return ac
}

// IncapsulaCerts accepts a slice of Secrets and returns only those configured
// for replication to Incapsula
func IncapsulaCerts(s []corev1.Secret) []corev1.Secret {
	var c []corev1.Secret
	for _, v := range s {
		if v.Annotations["cert-manager-sync.lestak.sh/incapsula-site-id"] != "" {
			c = append(c, v)
		}
	}
	return c
}

// secretToCert converts a k8s secret to a properly-formatted TLS Certificate
func secretToCert(s corev1.Secret) *Certificate {
	return separateCerts(s.Data["ca.crt"], s.Data["tls.crt"], s.Data["tls.key"])
}

// secretToACMInput converts a k8s secret to a properly-formatted ACM Import object
func secretToACMInput(s corev1.Secret) (*acm.ImportCertificateInput, error) {
	l := log.WithFields(
		log.Fields{
			"action":     "secretToACMInput",
			"secretName": s.ObjectMeta.Name,
		},
	)
	im := separateCertsACM(s.Data["ca.crt"], s.Data["tls.crt"], s.Data["tls.key"])
	// secret already has an aws acm cert attached
	if s.ObjectMeta.Annotations["cert-manager-sync.lestak.sh/acm-certificate-arn"] != "" {
		im.CertificateArn = aws.String(s.ObjectMeta.Annotations["cert-manager-sync.lestak.sh/acm-certificate-arn"])
	} else {
		// this is our first time sending to ACM, tag
		var tags []*acm.Tag
		tags = append(tags, &acm.Tag{
			Key:   aws.String("cert-manager-sync.lestak.sh/secret-name"),
			Value: aws.String(s.ObjectMeta.Name),
		})
		im.Tags = tags
	}
	l.Print("secretToACMInput")
	return im, nil
}

// replicateACMCert takes an ACM ImportCertificateInput and replicates it to AWS CertificateManager
func replicateACMCert(ai *acm.ImportCertificateInput) (string, error) {
	var arn string
	l := log.WithFields(
		log.Fields{
			"action": "replicateACMCert",
		},
	)
	l.Print("replicateACMCert")
	// inefficient creation of session on each import - can be cached
	sess, serr := CreateAWSSession()
	if serr != nil {
		l.Printf("CreateAWSSession error=%v", serr)
		return arn, serr
	}
	c, cerr := ImportCertificate(sess, ai, "")
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
	certArn, cerr := replicateACMCert(ai)
	if cerr != nil {
		l.Print(cerr)
		return cerr
	}
	s.ObjectMeta.Annotations["cert-manager-sync.lestak.sh/acm-certificate-arn"] = certArn
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

// handleACMCerts handles the sync of all ACM-enabled certs
func handleACMCerts(ss []corev1.Secret) error {
	ss = ACMCerts(ss)
	l := log.WithFields(
		log.Fields{
			"action": "handleACMCerts",
		},
	)
	l.Print("handleACMCerts")
	for _, s := range ss {
		err := handleACMCert(s)
		if err != nil {
			l.Printf("handleACMCert error=%v", err)
			return err
		}
	}
	return nil
}

// handleIncapsulaCerts handles the sync of all Incapsula-enabled certs
func handleIncapsulaCerts(ss []corev1.Secret) error {
	ss = IncapsulaCerts(ss)
	l := log.WithFields(
		log.Fields{
			"action": "handleIncapsulaCerts",
		},
	)
	l.Print("handleIncapsulaCerts")
	for _, s := range ss {
		is := &IncapsulaSecret{
			Name: s.Annotations["cert-manager-sync.lestak.sh/incapsula-secret-name"],
		}
		gerr := is.Get(context.Background())
		if gerr != nil {
			l.Printf("is.Get error=%v", gerr)
			return gerr
		}
		uerr := UploadIncapsulaCert(
			is,
			secretToCert(s),
			s.Annotations["cert-manager-sync.lestak.sh/incapsula-site-id"],
		)
		if uerr != nil {
			l.Printf("UploadIncapsulaCert error=%v", uerr)
			return uerr
		}
	}
	return nil
}

func init() {
	l := log.WithFields(
		log.Fields{
			"action": "init",
		},
	)
	l.Print("init")
	cerr := createKubeClient()
	if cerr != nil {
		l.Fatal(cerr)
	}
}

func main() {
	l := log.WithFields(
		log.Fields{
			"action": "main",
		},
	)
	// main loop
	for {
		l.Print("main loop")
		as, serr := getSecrets()
		if serr != nil {
			l.Fatal(serr)
		}
		go handleACMCerts(as)
		go handleIncapsulaCerts(as)
		l.Printf("sleep main loop")
		time.Sleep(time.Second * 60)
	}

}
