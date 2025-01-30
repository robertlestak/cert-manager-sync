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
	"strings"

	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type IncapsulaStore struct {
	ID              string `json:"api_id"`
	SiteID          string `json:"site_id"`
	Key             string `json:"api_key"`
	AuthType        string `json:"auth_type"`
	SecretName      string
	SecretNamespace string
}

func (s *IncapsulaStore) GetApiKey(ctx context.Context) error {
	gopt := metav1.GetOptions{}
	if s.SecretName == "" {
		return fmt.Errorf("secret name not set")
	}
	sc, err := state.KubeClient.CoreV1().Secrets(s.SecretNamespace).Get(ctx, s.SecretName, gopt)
	if err != nil {
		return err
	}
	s.ID = string(sc.Data["api_id"])
	s.Key = string(sc.Data["api_key"])
	return nil
}

func (s *IncapsulaStore) FromConfig(c tlssecret.GenericSecretSyncConfig) error {
	l := log.WithFields(log.Fields{
		"action": "FromConfig",
	})
	l.Debugf("FromConfig")
	if c.Config["site-id"] != "" {
		s.SiteID = c.Config["site-id"]
	}
	if c.Config["secret-name"] != "" {
		s.SecretName = c.Config["secret-name"]
	}
	if c.Config["auth-type"] != "" {
		s.AuthType = c.Config["auth-type"]
	} else {
		s.AuthType = "RSA"
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

type ImpervaCertUpload struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
	Passphrase  string `json:"passphrase,omitempty"`
	AuthType    string `json:"auth_type"`
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
	iurl := "https://my.imperva.com/api/prov/v2/sites/" + s.SiteID + "/customCertificate"
	up := &ImpervaCertUpload{
		Certificate: bCert,
		PrivateKey:  bKey,
		AuthType:    cmp.Or(s.AuthType, "RSA"),
	}
	jd, err := json.Marshal(up)
	if err != nil {
		l.WithError(err).Errorf("json.Marshal error")
		return err
	}
	l.Debugf("url=%s data=%s", iurl, string(jd))
	req, rerr := http.NewRequest("PUT", iurl, strings.NewReader(string(jd)))
	if rerr != nil {
		l.WithError(rerr).Errorf("http.NewRequest error")
		return rerr
	}
	req.Header.Set("x-api-id", s.ID)
	req.Header.Set("x-api-key", s.Key)
	req.Header.Set("Content-Type", "application/json")
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
	if res.StatusCode != 200 {
		l.Debugf("status=%v body=%s", res.StatusCode, string(bd))
		return fmt.Errorf("incapsula upload failed, incapsulaSecretNamespace=%s incapsulaSecret=%s statusCode=%d", s.SecretNamespace, s.SecretName, res.StatusCode)
	}
	ir := &IncapsulaResponse{}
	if err = json.Unmarshal(bd, ir); err != nil {
		l.WithError(err).Errorf("json.Unmarshal error")
		// debug dump the response
		l.Debugf("status=%v body=%s", res.StatusCode, string(bd))
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
	iurl := "https://my.imperva.com/api/prov/v1/sites/status"
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

func (s *IncapsulaStore) Sync(c *tlssecret.Certificate) (map[string]string, error) {
	s.SecretNamespace = c.Namespace
	l := log.WithFields(log.Fields{
		"action":          "Sync",
		"store":           "incapsula",
		"secretName":      s.SecretName,
		"secretNamespace": s.SecretNamespace,
		"siteID":          s.SiteID,
	})
	l.Debugf("Update")
	l = l.WithFields(log.Fields{
		"id": s.SiteID,
	})
	ctx := context.Background()
	if err := s.GetApiKey(ctx); err != nil {
		l.WithError(err).Errorf("incapsula.GetApiKey error")
		l.WithError(err).Errorf("sync error")
		return nil, err
	}
	bd, err := s.GetIncapsulaSiteStatus()
	if err != nil {
		l.WithError(err).Errorf("incapsula.GetIncapsulaSiteStatus error: %s", bd)
		l.WithError(err).Errorf("sync error")
		return nil, err
	}
	if err := s.UploadIncapsulaCert(c); err != nil {
		l.WithError(err).Errorf("incapsula.UploadIncapsulaCert error")
		l.WithError(err).Errorf("sync error")
		return nil, err
	}
	l.Info("certificate synced")
	return nil, nil
}
