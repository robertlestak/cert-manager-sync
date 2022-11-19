package main

import (
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
)

var (
	// k8sClient contains the kubernetes API client
	k8sClient    *kubernetes.Clientset
	operatorName string
	cache        []*Certificate
)

// Certificate represents a properly formatted TLS certificate
type Certificate struct {
	SecretName  string
	Annotations map[string]string
	Labels      map[string]string
	Chain       []byte
	Certificate []byte
	Key         []byte
}

func stringMapChanged(a, b map[string]string) bool {
	if len(a) != len(b) {
		return true
	}
	for k, v := range a {
		if b[k] != v {
			return true
		}
	}
	return false
}

func init() {
	ll, lerr := log.ParseLevel(os.Getenv("LOG_LEVEL"))
	if lerr != nil {
		ll = log.InfoLevel
	}
	log.SetLevel(ll)
	l := log.WithFields(
		log.Fields{
			"action": "init",
		},
	)
	l.Print("init")
	if os.Getenv("OPERATOR_NAME") == "" {
		l.Fatal("OPERATOR_NAME not set")
	} else {
		operatorName = os.Getenv("OPERATOR_NAME")
	}
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
	l.Debug("starting")
	// main loop
	for {
		l.Print("main loop")
		l.Debug("main loop getK8sSecrets")
		as, serr := getK8sSecrets()
		if serr != nil {
			l.Fatal(serr)
		}
		l.Debug("main handleK8sCertsForACM")
		go handleK8sCertsForACM(as)
		l.Debug("main handleK8sCertsForASM")
		go handleK8sCertsForASM(as)
		l.Debug("main handleIncapsulaCerts")
		go handleIncapsulaCerts(as)
		l.Debug("main handleThreatxCerts")
		go handleThreatxCerts(as)
		l.Printf("sleep main loop")
		l.Debug("main handleVaultCerts")
		go handleVaultCerts(as)
		time.Sleep(time.Second * 60)
	}
}
