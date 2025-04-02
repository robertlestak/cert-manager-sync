package tencentcloud

import (
	"cmp"
	"context"
	"crypto/x509"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
	"github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/common/profile"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/ssl/v20191205"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/robertlestak/cert-manager-sync/pkg/cert"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	"github.com/robertlestak/cert-manager-sync/stores"
)

type tencentcloudStore struct {
	certId string

	secretName       string
	secretNamespace  string
	secretIdKeyName  string // keyname of secretId in secret
	secretKeyKeyName string // keyname of secretKey in secret
	alias            string
	resources        string // resource types
	projectId        uint64
	repeatable       bool
}

type wrapLogger struct {
	*log.Logger
}

func (l *wrapLogger) Printf(format string, args ...interface{}) {
	l.Logger.Debugf(format, args...)
}

func (s *tencentcloudStore) getCrendential(ctx context.Context) (string, string, error) {
	gopt := metav1.GetOptions{}
	sc, err := state.KubeClient.CoreV1().Secrets(s.secretNamespace).Get(ctx, s.secretName, gopt)
	if err != nil {
		return "", "", err
	}
	secretId, err := tlssecret.GetValue(sc, cmp.Or(s.secretIdKeyName, "TENCENTCLOUD_SECRET_ID"))
	if err != nil {
		return "", "", err
	}
	secretKey, err := tlssecret.GetValue(sc, cmp.Or(s.secretKeyKeyName, "TENCENTCLOUD_SECRET_KEY"))
	if err != nil {
		return "", "", err
	}
	return string(secretId), string(secretKey), nil
}

func New(c tlssecret.GenericSecretSyncConfig) (stores.RemoteStore, error) {
	s := &tencentcloudStore{}
	if c.Config["secret-name"] != "" {
		s.secretName = c.Config["secret-name"]
	}
	if c.Config["secret-namespace"] != "" {
		s.secretNamespace = c.Config["secret-namespace"]
	}
	if strings.Contains(s.secretName, "/") {
		if parts := strings.Split(s.secretName, "/"); len(parts) == 2 {
			s.secretNamespace = parts[0]
			s.secretName = parts[1]
		}
	}
	if s.secretName == "" {
		return nil, stores.ErrSecretNameNotFound
	}
	if s.secretNamespace == "" {
		return nil, stores.ErrSecretNamespaceNotFound
	}
	if v := c.Config["cert-id"]; v != "" {
		s.certId = v
	}
	if v := c.Config["secretIdKeyName"]; v != "" {
		s.secretIdKeyName = v
	}
	if v := c.Config["secretKeyKeyName"]; v != "" {
		s.secretKeyKeyName = v
	}
	if v := c.Config["alias"]; v != "" {
		s.alias = v
	}
	if v := c.Config["projectId"]; v != "" {
		i, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return nil, err
		}
		s.projectId = i
	}
	if v := c.Config["resources"]; v != "" {
		s.resources = v
	} else if s.certId != "" {
		// for UpdateCertificateInstance
		return nil, errors.New("'tencentcloud-resources' must included in secret annotation for tencentcloud store")
	}
	if v := c.Config["repeatable"]; v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, err
		}
		s.repeatable = b
	}

	return s, nil
}

func (s *tencentcloudStore) Sync(c *tlssecret.Certificate) (map[string]string, error) {
	l := log.WithFields(log.Fields{
		"action":          "Sync",
		"store":           "tencentcloud",
		"secretName":      s.secretName,
		"secretNamespace": s.secretNamespace,
	})

	ctx := context.Background()
	secretId, secretKey, err := s.getCrendential(ctx)
	if err != nil {
		l.WithError(err).Errorf("getCrendential error")
		return nil, err
	}

	credential := common.NewCredential(secretId, secretKey)
	clientProfile := profile.NewClientProfile()
	if log.IsLevelEnabled(log.DebugLevel) {
		clientProfile.Debug = true
	}
	client, err := ssl.NewClient(credential, "", clientProfile)
	if err != nil {
		l.WithError(err).Errorf("tencentcloudssl.NewClient error")
		return nil, err
	}
	if log.IsLevelEnabled(log.DebugLevel) {
		client.WithLogger(&wrapLogger{l.Logger})
	}

	origCertId := s.certId

	if s.certId == "" {
		l.Debugf("Upload new certificate")
		req := ssl.NewUploadCertificateRequest()
		req.Alias = &s.alias
		req.Repeatable = &s.repeatable
		req.ProjectId = &s.projectId
		req.CertificateUse = &s.resources
		req.CertificatePublicKey = ptr(string(c.Certificate))
		req.CertificatePrivateKey = ptr(string(c.Key))
		resp, err := client.UploadCertificate(req)
		if err != nil {
			return nil, err
		}
		s.certId = *resp.Response.CertificateId
	} else {
		l.Debugf("Update certificate")
		req := ssl.NewUpdateCertificateInstanceRequest()
		req.CertificateId = &s.certId
		req.Repeatable = &s.repeatable
		req.ProjectId = &s.projectId
		req.CertificatePublicKey = ptr(string(c.Certificate))
		req.CertificatePrivateKey = ptr(string(c.Key))
		req.OldCertificateId = &s.certId
		if s.resources != "" {
			parts := strings.Split(s.resources, ",")
			for i := range parts {
				req.ResourceTypes = append(req.ResourceTypes, ptr(parts[i]))
			}
		}
		resp, err := client.UpdateCertificateInstance(req)
		if err != nil {
			return nil, err
		}
		l.Debug(resp.ToJsonString())
		// as UpdateCertificateInstanceRequest won't return the newly created certId
		// so describe the related certificates and filter it out
		crt, err := cert.ParseCertificateFromBytes(c.Certificate)
		if err != nil {
			return nil, err
		}
		certId, err := waitForNewCert(client, s.certId, crt)
		if err != nil {
			return nil, err
		}
		s.certId = certId
	}

	l = l.WithField("id", s.certId)
	var newKeys map[string]string
	if origCertId != s.certId {
		newKeys = map[string]string{
			"cert-id": s.certId,
		}
	}
	l.Info("certificate synced")
	return newKeys, nil
}

const maxAllowedTimeSkew = time.Minute * 3

func waitForNewCert(c *ssl.Client, origCertId string, crt *x509.Certificate) (string, error) {
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		return "", err
	}
	getNewCertId := func() (string, error) {
		req := ssl.NewDescribeCertificatesRequest()
		req.FilterSource = ptr("upload")
		req.ExpirationSort = ptr("DESC")
		req.SearchKey = ptr(origCertId)
		resp, err := c.DescribeCertificates(req)
		if err != nil {
			return "", err
		}
		for _, cert := range resp.Response.Certificates {
			bt, err := time.ParseInLocation(time.DateTime, *cert.CertBeginTime, loc)
			if err != nil {
				return "", backoff.Permanent(err)
			}
			et, err := time.ParseInLocation(time.DateTime, *cert.CertEndTime, loc)
			if err != nil {
				return "", backoff.Permanent(err)
			}
			log.Debug(crt.NotBefore, crt.NotAfter, bt, et)

			if crt.NotBefore.Sub(bt).Abs() < maxAllowedTimeSkew && crt.NotAfter.Sub(et).Abs() < maxAllowedTimeSkew {
				return *cert.CertificateId, nil
			}
			if cert.CertificateId != &origCertId && strings.Contains(*cert.Alias, origCertId) {
				return *cert.CertificateId, nil
			}
		}
		return "", errors.New("newly created associated certificate not found yet")
	}
	return backoff.RetryWithData(getNewCertId, backoff.NewExponentialBackOff())
}

func ptr[T any](v T) *T {
	return &v
}

func init() {
	stores.Register("tencentcloud", stores.StoreCreatorFunc(New))
}
