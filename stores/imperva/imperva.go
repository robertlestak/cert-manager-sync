package imperva

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

type ImpervaStore struct {
	ID              string `json:"api_id"`
	SiteID          string `json:"site_id"`
	Key             string `json:"api_key"`
	AuthType        string `json:"auth_type"`
	SecretName      string
	SecretNamespace string
}

func (s *ImpervaStore) GetApiKey(ctx context.Context) error {
	gopt := metav1.GetOptions{}
	if s.SecretName == "" {
		return fmt.Errorf("secret name not set")
	}
	sc, err := state.KubeClient.CoreV1().Secrets(s.SecretNamespace).Get(ctx, s.SecretName, gopt)
	if err != nil {
		return fmt.Errorf("failed to get Imperva credentials secret %s/%s: %w", s.SecretNamespace, s.SecretName, err)
	}
	s.ID = string(sc.Data["api_id"])
	s.Key = string(sc.Data["api_key"])
	return nil
}

func (s *ImpervaStore) FromConfig(c tlssecret.GenericSecretSyncConfig) error {
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

// ImpervaResponse contains the response from Imperva API
type ImpervaResponse struct {
	Res        int    `json:"res"`
	ResMessage string `json:"res_message"`
}

type ImpervaCertUpload struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
	Passphrase  string `json:"passphrase,omitempty"`
	AuthType    string `json:"auth_type"`
}

// UploadImpervaCert syncs a certificate with Imperva site
func (s *ImpervaStore) UploadImpervaCert(cert *tlssecret.Certificate) error {
	l := log.WithFields(
		log.Fields{
			"action": "UploadImpervaCert",
			"siteID": s.SiteID,
		},
	)
	l.Debugf("UploadImpervaCert")
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
		return fmt.Errorf("failed to marshal Imperva certificate upload request: %w", err)
	}
	l.Debugf("url=%s data=%s", iurl, string(jd))
	req, rerr := http.NewRequest("PUT", iurl, strings.NewReader(string(jd)))
	if rerr != nil {
		l.WithError(rerr).Errorf("http.NewRequest error")
		return fmt.Errorf("failed to create Imperva API request for site %s: %w", s.SiteID, rerr)
	}
	req.Header.Set("x-api-id", s.ID)
	req.Header.Set("x-api-key", s.Key)
	req.Header.Set("Content-Type", "application/json")
	res, serr := c.Do(req)
	if serr != nil {
		l.WithError(serr).Errorf("c.Do error=%v", serr)
		return fmt.Errorf("failed to upload certificate to Imperva site %s: %w", s.SiteID, serr)
	}
	defer res.Body.Close()
	bd, berr := io.ReadAll(res.Body)
	if berr != nil {
		l.WithError(berr).Errorf("io.ReadAll error")
		return fmt.Errorf("failed to read Imperva API response for site %s: %w", s.SiteID, berr)
	}
	if res.StatusCode != 200 {
		l.Debugf("status=%v body=%s", res.StatusCode, string(bd))
		return fmt.Errorf("imperva upload failed for site %s (status: %d, secret: %s/%s): %s", s.SiteID, res.StatusCode, s.SecretNamespace, s.SecretName, string(bd))
	}
	ir := &ImpervaResponse{}
	if err = json.Unmarshal(bd, ir); err != nil {
		l.WithError(err).Errorf("json.Unmarshal error")
		// debug dump the response
		l.Debugf("status=%v body=%s", res.StatusCode, string(bd))
		return fmt.Errorf("failed to parse Imperva API response for site %s: %w", s.SiteID, err)
	}
	l.Debugf("imperva statusCode=%d response=%v", res.StatusCode, string(bd))
	if ir.Res != 0 {
		l.Debugf("status=%v body=%s", res.StatusCode, string(bd))
		return fmt.Errorf("imperva upload failed for site %s (secret: %s/%s): %s", s.SiteID, s.SecretNamespace, s.SecretName, string(bd))
	}
	l.Debugf("imperva response=%v", string(bd))
	return err
}

func (s *ImpervaStore) GetImpervaSiteStatus() (string, error) {
	l := log.WithFields(
		log.Fields{
			"action": "GetImpervaSiteStatus",
			"siteID": s.SiteID,
		},
	)
	l.Debugf("GetImpervaSiteStatus")
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
	ir := &ImpervaResponse{}
	if err = json.Unmarshal(bd, ir); err != nil {
		l.WithError(err).Errorf("json.Unmarshal error")
		return string(bd), err
	}
	l.Debugf("imperva statusCode=%d response=%v", res.StatusCode, string(bd))
	if ir.Res != 0 {
		l.Debugf("status=%v body=%s", res.StatusCode, string(bd))
		return string(bd), fmt.Errorf("imperva upload failed, body=%s", string(bd))
	}
	l.Debugf("imperva response=%v", string(bd))
	return string(bd), err
}

func (s *ImpervaStore) Sync(c *tlssecret.Certificate) (map[string]string, error) {
	s.SecretNamespace = c.Namespace
	l := log.WithFields(log.Fields{
		"action":          "Sync",
		"store":           "imperva",
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
		l.WithError(err).Errorf("imperva.GetApiKey error")
		l.WithError(err).Errorf("sync error")
		return nil, err
	}
	bd, err := s.GetImpervaSiteStatus()
	if err != nil {
		l.WithError(err).Errorf("imperva.GetImpervaSiteStatus error: %s", bd)
		l.WithError(err).Errorf("sync error")
		return nil, err
	}
	if err := s.UploadImpervaCert(c); err != nil {
		l.WithError(err).Errorf("imperva.UploadImpervaCert error")
		l.WithError(err).Errorf("sync error")
		return nil, err
	}
	l.Info("certificate synced")
	return nil, nil
}
