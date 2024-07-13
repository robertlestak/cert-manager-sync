package incapsula

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type IncapsulaStore struct {
	ID              string `json:"api_id"`
	SiteID          string `json:"site_id"`
	Key             string `json:"api_key"`
	SecretName      string
	SecretNamespace string
}

func impervaApiBase() string {
	fromEnv := cmp.Or(os.Getenv("INCAPSULA_API"), os.Getenv("IMPERVA_API"))
	fromEnv = cmp.Or(fromEnv, "https://my.imperva.com/api/prov/v1")
	return fromEnv
}

func (s *IncapsulaStore) GetApiKey(ctx context.Context) error {
	gopt := metav1.GetOptions{}
	sc, err := state.KubeClient.CoreV1().Secrets(s.SecretNamespace).Get(ctx, s.SecretName, gopt)
	if err != nil {
		return err
	}
	s.ID = string(sc.Data["api_id"])
	s.Key = string(sc.Data["api_key"])
	return nil
}

func (s *IncapsulaStore) ParseCertificate(c *tlssecret.Certificate) error {
	l := log.WithFields(log.Fields{
		"action": "ParseCertificate",
	})
	l.Debugf("ParseCertificate")
	if c.Annotations[state.OperatorName+"/incapsula-site-id"] != "" {
		s.SiteID = c.Annotations[state.OperatorName+"/incapsula-site-id"]
	}
	if c.Annotations[state.OperatorName+"/incapsula-secret-name"] != "" {
		s.SecretName = c.Annotations[state.OperatorName+"/incapsula-secret-name"]
	}
	// if secret name is in the format of "namespace/secretname" then parse it
	if strings.Contains(s.SecretName, "/") {
		s.SecretNamespace = strings.Split(s.SecretName, "/")[0]
		s.SecretName = strings.Split(s.SecretName, "/")[1]
	}
	return nil
}

// Incapsula response contains the response from Incapsula API
type IncapsulaResponse struct {
	Res        int    `json:"res"`
	ResMessage string `json:"res_message"`
}

// UploadIncapsulaCert syncs a certificate with Incapsula site
func (s *IncapsulaStore) UploadIncapsulaCert(cert *tlssecret.Certificate) error {
	l := log.WithFields(
		log.Fields{
			"action": "UploadIncapsulaCert",
			"siteID": s.SiteID,
		},
	)
	l.Debugf("UploadIncapsulaCert")
	var err error
	bCert := base64.StdEncoding.EncodeToString(cert.FullChain())
	bKey := base64.StdEncoding.EncodeToString(cert.Key)
	c := http.Client{}
	iurl := impervaApiBase() + "/sites/customCertificate/upload"
	data := url.Values{}
	data.Set("site_id", s.SiteID)
	data.Set("certificate", bCert)
	data.Set("private_key", bKey)
	d := strings.NewReader(data.Encode())
	l.Debugf("url=%s data=%s", iurl, data.Encode())
	req, rerr := http.NewRequest("POST", iurl, d)
	if rerr != nil {
		l.WithError(rerr).Errorf("http.NewRequest error")
		return rerr
	}
	req.Header.Set("x-api-id", s.ID)
	req.Header.Set("x-api-key", s.Key)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, serr := c.Do(req)
	if serr != nil {
		l.WithError(serr).Errorf("c.Do error=%v", serr)
		return serr
	}
	defer res.Body.Close()
	bd, berr := io.ReadAll(res.Body)
	if berr != nil {
		l.WithError(berr).Errorf("io.ReadAll error")
		return berr
	}
	ir := &IncapsulaResponse{}
	if err = json.Unmarshal(bd, ir); err != nil {
		l.WithError(err).Errorf("json.Unmarshal error")
		return err
	}
	l.Debugf("incapsula statusCode=%d response=%v", res.StatusCode, string(bd))
	if ir.Res != 0 {
		l.Debugf("status=%v body=%s", res.StatusCode, string(bd))
		return fmt.Errorf("incapsula upload failed, incapsulaSecretNamespace=%s incapsulaSecret=%s body=%s", s.SecretNamespace, s.SecretName, string(bd))
	}
	l.Debugf("incapsula response=%v", string(bd))
	return err
}

func (s *IncapsulaStore) GetIncapsulaSiteStatus() (string, error) {
	l := log.WithFields(
		log.Fields{
			"action": "GetIncapsulaSiteStatus",
			"siteID": s.SiteID,
		},
	)
	l.Debugf("GetIncapsulaSiteStatus")
	var err error
	iurl := impervaApiBase() + "/sites/status"
	c := http.Client{}
	data := url.Values{}
	data.Set("site_id", s.SiteID)
	data.Set("tests", "services")
	d := strings.NewReader(data.Encode())
	l.Debugf("url=%s data=%s", iurl, data.Encode())
	req, rerr := http.NewRequest("POST", iurl, d)
	if rerr != nil {
		l.WithError(rerr).Errorf("http.NewRequest error")
		return "", rerr
	}
	req.Header.Set("x-api-id", s.ID)
	req.Header.Set("x-api-key", s.Key)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, serr := c.Do(req)
	if serr != nil {
		l.WithError(serr).Errorf("c.Do error=%v", serr)
		return "", serr
	}
	defer res.Body.Close()
	bd, berr := io.ReadAll(res.Body)
	if berr != nil {
		l.WithError(berr).Errorf("ioutil.ReadAll error")
		return "", berr
	}
	ir := &IncapsulaResponse{}
	if err = json.Unmarshal(bd, ir); err != nil {
		l.WithError(err).Errorf("json.Unmarshal error")
		return string(bd), err
	}
	l.Debugf("incapsula statusCode=%d response=%v", res.StatusCode, string(bd))
	if ir.Res != 0 {
		l.Debugf("status=%v body=%s", res.StatusCode, string(bd))
		return string(bd), fmt.Errorf("incapsula upload failed, body=%s", string(bd))
	}
	l.Debugf("incapsula response=%v", string(bd))
	return string(bd), err
}

func (s *IncapsulaStore) Update(secret *corev1.Secret) error {
	l := log.WithFields(log.Fields{
		"action":          "Update",
		"store":           "incapsula",
		"secretName":      secret.ObjectMeta.Name,
		"secretNamespace": secret.ObjectMeta.Namespace,
	})
	l.Debugf("Update")
	c := tlssecret.ParseSecret(secret)
	if err := s.ParseCertificate(c); err != nil {
		l.WithError(err).Errorf("incapsula.ParseCertificate error")
		return err
	}
	if s.SecretNamespace == "" {
		s.SecretNamespace = secret.Namespace
	}
	l = l.WithFields(log.Fields{
		"siteID": s.SiteID,
	})
	ctx := context.Background()
	if err := s.GetApiKey(ctx); err != nil {
		l.WithError(err).Errorf("incapsula.GetApiKey error")
		return err
	}
	_, err := s.GetIncapsulaSiteStatus()
	if err != nil {
		l.WithError(err).Errorf("incapsula.GetIncapsulaSiteStatus error")
		return err
	}
	if err := s.UploadIncapsulaCert(c); err != nil {
		l.WithError(err).Errorf("incapsula.UploadIncapsulaCert error")
		return err
	}
	l.Info("certificate synced")
	return nil
}
