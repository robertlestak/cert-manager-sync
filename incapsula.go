package main

import (
	"context"
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IncapsulaSecret contains a single Incapsula API Secret
type IncapsulaSecret struct {
	Name   string `json:"name"`
	ID     string `json:"api_id"`
	SiteID string `json:"site_id"`
	Key    string `json:"api_key"`
}

// Get retrieves a single Incapsula secret by name from k8s secrets
func (s *IncapsulaSecret) Get(ctx context.Context) error {
	gopt := metav1.GetOptions{}
	sc, err := k8sClient.CoreV1().Secrets(os.Getenv("SECRETS_NAMESPACE")).Get(ctx, s.Name, gopt)
	if err != nil {
		return err
	}
	s.ID = string(sc.Data["api_id"])
	s.Key = string(sc.Data["api_key"])
	return nil
}

// UploadIncapsulaCert syncs a certificate with Incapsula site
func UploadIncapsulaCert(sec *IncapsulaSecret, cert *Certificate, siteID string) error {
	l := log.WithFields(
		log.Fields{
			"action": "UploadIncapsulaCert",
		},
	)
	l.Print("UploadIncapsulaCert")
	var err error
	bCert := base64.StdEncoding.EncodeToString(append(cert.Certificate[:], cert.Chain[:]...))
	bKey := base64.StdEncoding.EncodeToString(cert.Key)
	c := http.Client{}
	iurl := os.Getenv("INCAPSULA_API") + "/sites/customCertificate/upload"
	data := url.Values{}
	data.Set("api_id", sec.ID)
	data.Set("site_id", siteID)
	data.Set("api_key", sec.Key)
	data.Set("certificate", bCert)
	data.Set("private_key", bKey)
	d := strings.NewReader(data.Encode())
	req, rerr := http.NewRequest("POST", iurl, d)
	if rerr != nil {
		l.Printf("http.NewRequest error=%v", rerr)
		return rerr
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, serr := c.Do(req)
	if serr != nil {
		l.Printf("c.Do error=%v", serr)
		return serr
	}
	defer res.Body.Close()
	bd, berr := ioutil.ReadAll(res.Body)
	if berr != nil {
		l.Printf("ioutil.ReadAll error=%v", berr)
		return berr
	}
	l.Printf("incapsula response=%v", string(bd))
	return err
}

func GetIncapsulaSiteStatus(sec *IncapsulaSecret, siteID string) (string, error) {
	l := log.WithFields(
		log.Fields{
			"action": "GetIncapsulaSiteStatus",
		},
	)
	l.Print("GetIncapsulaSiteStatus")
	var err error
	iurl := os.Getenv("INCAPSULA_API") + "/sites/status"
	c := http.Client{}
	data := url.Values{}
	data.Set("api_id", sec.ID)
	data.Set("site_id", siteID)
	data.Set("api_key", sec.Key)
	data.Set("tests", "services")
	d := strings.NewReader(data.Encode())
	req, rerr := http.NewRequest("POST", iurl, d)
	if rerr != nil {
		l.Printf("http.NewRequest error=%v", rerr)
		return "", rerr
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, serr := c.Do(req)
	if serr != nil {
		l.Printf("c.Do error=%v", serr)
		return "", serr
	}
	defer res.Body.Close()
	bd, berr := ioutil.ReadAll(res.Body)
	if berr != nil {
		l.Printf("ioutil.ReadAll error=%v", berr)
		return "", berr
	}
	//l.Printf("incapsula response=%v", string(bd))
	return string(bd), err
}
