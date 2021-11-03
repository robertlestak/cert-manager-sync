package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
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

// Incapsula response contains the response from Incapsula API
type IncapsulaResponse struct {
	Res        int    `json:"res"`
	ResMessage string `json:"res_message"`
}

// UploadIncapsulaCert syncs a certificate with Incapsula site
func UploadIncapsulaCert(sec *IncapsulaSecret, cert *Certificate, siteID string) error {
	l := log.WithFields(
		log.Fields{
			"action": "UploadIncapsulaCert",
			"siteID": siteID,
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
	l.Debugf("url=%s data=%s", iurl, data.Encode())
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
	ir := &IncapsulaResponse{}
	if err = json.Unmarshal(bd, ir); err != nil {
		l.Printf("json.Unmarshal error=%v", err)
		return err
	}
	l.Debugf("incapsula statusCode=%d response=%v", res.StatusCode, string(bd))
	if ir.Res != 0 {
		l.Printf("status=%v body=%s", res.StatusCode, string(bd))
		return fmt.Errorf("incapsula upload failed, body=%s", string(bd))
	}
	l.Debugf("incapsula response=%v", string(bd))
	return err
}

func GetIncapsulaSiteStatus(sec *IncapsulaSecret, siteID string) (string, error) {
	l := log.WithFields(
		log.Fields{
			"action": "GetIncapsulaSiteStatus",
			"siteID": siteID,
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
	l.Debugf("url=%s data=%s", iurl, data.Encode())
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
	ir := &IncapsulaResponse{}
	if err = json.Unmarshal(bd, ir); err != nil {
		l.Printf("json.Unmarshal error=%v", err)
		return string(bd), err
	}
	l.Debugf("incapsula statusCode=%d response=%v", res.StatusCode, string(bd))
	if ir.Res != 0 {
		l.Printf("status=%v body=%s", res.StatusCode, string(bd))
		return string(bd), fmt.Errorf("incapsula upload failed, body=%s", string(bd))
	}
	l.Debugf("incapsula response=%v", string(bd))
	return string(bd), err
}

// IncapsulaCerts accepts a slice of Secrets and returns only those configured
// for replication to Incapsula
func IncapsulaCerts(s []corev1.Secret) []corev1.Secret {
	var c []corev1.Secret
	for _, v := range s {
		if v.Annotations[operatorName+"/incapsula-site-id"] != "" && cacheChanged(v) {
			c = append(c, v)
		}
	}
	return c
}

// handleIncapsulaCerts handles the sync of all Incapsula-enabled certs
func handleIncapsulaCerts(ss []corev1.Secret) {
	ss = IncapsulaCerts(ss)
	l := log.WithFields(
		log.Fields{
			"action": "handleIncapsulaCerts",
		},
	)
	l.Print("handleIncapsulaCerts")
	for i, s := range ss {
		l.Debugf("processing secret %s (%d/%d)", s.ObjectMeta.Name, i+1, len(ss))
		is := &IncapsulaSecret{
			Name: s.Annotations[operatorName+"/incapsula-secret-name"],
		}
		gerr := is.Get(context.Background())
		if gerr != nil {
			l.WithFields(log.Fields{
				"siteID":     s.Annotations[operatorName+"/incapsula-site-id"],
				"secretName": s.Annotations[operatorName+"/incapsula-secret-name"],
			}).Printf("is.Get error=%v", gerr)
			continue
		}
		// ensure site has ssl enabled befure uploading cert
		_, serr := GetIncapsulaSiteStatus(
			is,
			s.Annotations[operatorName+"/incapsula-site-id"],
		)
		if serr != nil {
			l.WithFields(log.Fields{
				"siteID":     s.Annotations[operatorName+"/incapsula-site-id"],
				"secretName": s.Annotations[operatorName+"/incapsula-secret-name"],
			}).Printf("GetIncapsulaSiteStatus error=%v", serr)
			continue
		}
		c := secretToCert(s)
		uerr := UploadIncapsulaCert(
			is,
			c,
			s.Annotations[operatorName+"/incapsula-site-id"],
		)
		if uerr != nil {
			l.WithFields(log.Fields{
				"siteID":     s.Annotations[operatorName+"/incapsula-site-id"],
				"secretName": s.Annotations[operatorName+"/incapsula-secret-name"],
			}).Printf("UploadIncapsulaCert error=%v", uerr)
			continue
		}
		addToCache(c)
	}
}
