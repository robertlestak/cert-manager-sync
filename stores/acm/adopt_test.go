package acm

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/acm"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubACM records what the store asked of ACM and replays canned responses.
type stubACM struct {
	summaries []*acm.CertificateSummary
	listErr   error
	tags      map[string][]*acm.Tag
	tagErrs   map[string]error

	tagCalls  []string
	imports   []*acm.ImportCertificateInput
	newArn    string
	listCalls int
}

func (s *stubACM) ListCertificatesPages(_ *acm.ListCertificatesInput, fn func(*acm.ListCertificatesOutput, bool) bool) error {
	s.listCalls++
	if s.listErr != nil {
		return s.listErr
	}
	fn(&acm.ListCertificatesOutput{CertificateSummaryList: s.summaries}, true)
	return nil
}

func (s *stubACM) ListTagsForCertificate(in *acm.ListTagsForCertificateInput) (*acm.ListTagsForCertificateOutput, error) {
	arn := aws.StringValue(in.CertificateArn)
	s.tagCalls = append(s.tagCalls, arn)
	if err, ok := s.tagErrs[arn]; ok {
		return nil, err
	}
	return &acm.ListTagsForCertificateOutput{Tags: s.tags[arn]}, nil
}

func (s *stubACM) ImportCertificate(in *acm.ImportCertificateInput) (*acm.ImportCertificateOutput, error) {
	s.imports = append(s.imports, in)
	if in.CertificateArn != nil {
		// ACM updates in place and echoes the same ARN back.
		return &acm.ImportCertificateOutput{CertificateArn: in.CertificateArn}, nil
	}
	return &acm.ImportCertificateOutput{CertificateArn: aws.String(s.newArn)}, nil
}

func (s *stubACM) DeleteCertificate(*acm.DeleteCertificateInput) (*acm.DeleteCertificateOutput, error) {
	return &acm.DeleteCertificateOutput{}, nil
}

// useStubACM installs stub as the store's ACM client for the test.
func useStubACM(t *testing.T, stub *stubACM) {
	t.Helper()
	prev := newACMClientFn
	newACMClientFn = func(*session.Session, *aws.Config) acmAPI { return stub }
	t.Cleanup(func() { newACMClientFn = prev })
}

// testCert builds a Certificate whose leaf carries CN=localhost.
func testCert(t *testing.T, namespace, name string) *tlssecret.Certificate {
	t.Helper()
	key, err := GenerateKey()
	require.NoError(t, err)
	crt, _, err := GenerateCert(key)
	require.NoError(t, err)
	return &tlssecret.Certificate{
		SecretName:  name,
		Namespace:   namespace,
		Certificate: crt,
		Key:         key,
	}
}

func summary(arn, domain string, inUse bool, imported time.Time) *acm.CertificateSummary {
	return &acm.CertificateSummary{
		CertificateArn: aws.String(arn),
		DomainName:     aws.String(domain),
		InUse:          aws.Bool(inUse),
		ImportedAt:     aws.Time(imported),
	}
}

func ourTag(namespace, name string) []*acm.Tag {
	return []*acm.Tag{{
		Key:   aws.String(state.OperatorName + "/secret-name"),
		Value: aws.String(namespace + "/" + name),
	}}
}

func TestAdoptExisting_OptInPrecedence(t *testing.T) {
	t.Setenv("ACM_ADOPT_EXISTING", "")
	s := &ACMStore{}
	// Off by default: two clusters syncing same-named secrets into one account
	// share a tag, and adopting there would have them overwrite each other.
	assert.False(t, s.adoptExisting(), "adoption must be opt-in")

	t.Setenv("ACM_ADOPT_EXISTING", "true")
	assert.True(t, s.adoptExisting(), "cluster-wide default applies when unset per-secret")

	require.NoError(t, s.FromConfig(tlssecret.GenericSecretSyncConfig{
		Config: map[string]string{"adopt-existing": "false"},
	}))
	assert.False(t, s.adoptExisting(), "per-secret annotation must win over the env default")

	require.NoError(t, s.FromConfig(tlssecret.GenericSecretSyncConfig{
		Config: map[string]string{"adopt-existing": "true"},
	}))
	t.Setenv("ACM_ADOPT_EXISTING", "false")
	assert.True(t, s.adoptExisting(), "per-secret opt-in must win over the env default")
}

func TestFindAdoptableCertificate(t *testing.T) {
	c := testCert(t, "cert-manager", "example")
	old := time.Now().Add(-72 * time.Hour)
	recent := time.Now().Add(-time.Hour)

	t.Run("adopts the certificate carrying our tag", func(t *testing.T) {
		stub := &stubACM{
			summaries: []*acm.CertificateSummary{summary("arn:ours", "localhost", false, old)},
			tags:      map[string][]*acm.Tag{"arn:ours": ourTag("cert-manager", "example")},
		}
		s := &ACMStore{}
		assert.Equal(t, "arn:ours", s.findAdoptableCertificate(stub, c))
	})

	t.Run("ignores another secret's certificate", func(t *testing.T) {
		stub := &stubACM{
			summaries: []*acm.CertificateSummary{summary("arn:theirs", "localhost", false, old)},
			tags:      map[string][]*acm.Tag{"arn:theirs": ourTag("cert-manager", "other")},
		}
		s := &ACMStore{}
		assert.Empty(t, s.findAdoptableCertificate(stub, c), "a different secret's tag must not match")
	})

	t.Run("ignores an untagged certificate", func(t *testing.T) {
		stub := &stubACM{
			summaries: []*acm.CertificateSummary{summary("arn:manual", "localhost", true, old)},
			tags:      map[string][]*acm.Tag{"arn:manual": nil},
		}
		s := &ACMStore{}
		assert.Empty(t, s.findAdoptableCertificate(stub, c),
			"a certificate we did not import must never be adopted")
	})

	t.Run("skips candidates whose domain cannot match", func(t *testing.T) {
		stub := &stubACM{
			summaries: []*acm.CertificateSummary{
				summary("arn:elsewhere", "unrelated.example.com", false, old),
				summary("arn:ours", "localhost", false, old),
			},
			tags: map[string][]*acm.Tag{"arn:ours": ourTag("cert-manager", "example")},
		}
		s := &ACMStore{}
		assert.Equal(t, "arn:ours", s.findAdoptableCertificate(stub, c))
		// The domain is free in the listing; the tag costs a call per candidate.
		assert.Equal(t, []string{"arn:ours"}, stub.tagCalls,
			"domain narrowing must keep us from paying a tag lookup on every certificate in the account")
	})

	t.Run("prefers the certificate in use", func(t *testing.T) {
		stub := &stubACM{
			summaries: []*acm.CertificateSummary{
				summary("arn:orphan", "localhost", false, recent),
				summary("arn:live", "localhost", true, old),
			},
			tags: map[string][]*acm.Tag{
				"arn:orphan": ourTag("cert-manager", "example"),
				"arn:live":   ourTag("cert-manager", "example"),
			},
		}
		s := &ACMStore{}
		// Adopting the orphan would freeze the certificate a load balancer is
		// actually serving, which is worse than the duplicate itself.
		assert.Equal(t, "arn:live", s.findAdoptableCertificate(stub, c),
			"an in-use certificate must win even when an orphan is newer")
	})

	t.Run("falls back to the newest when none are in use", func(t *testing.T) {
		stub := &stubACM{
			summaries: []*acm.CertificateSummary{
				summary("arn:older", "localhost", false, old),
				summary("arn:newer", "localhost", false, recent),
			},
			tags: map[string][]*acm.Tag{
				"arn:older": ourTag("cert-manager", "example"),
				"arn:newer": ourTag("cert-manager", "example"),
			},
		}
		s := &ACMStore{}
		assert.Equal(t, "arn:newer", s.findAdoptableCertificate(stub, c))
	})

	t.Run("denied listing degrades to a plain import", func(t *testing.T) {
		stub := &stubACM{listErr: awserr.New("AccessDeniedException", "no acm:ListCertificates", nil)}
		s := &ACMStore{}
		// Adoption is an optimization. A missing permission must not fail the
		// sync -- it just reproduces the behavior of not having the feature.
		assert.Empty(t, s.findAdoptableCertificate(stub, c))
	})

	t.Run("denied tag read skips the candidate", func(t *testing.T) {
		stub := &stubACM{
			summaries: []*acm.CertificateSummary{
				summary("arn:opaque", "localhost", false, old),
				summary("arn:ours", "localhost", false, old),
			},
			tagErrs: map[string]error{"arn:opaque": awserr.New("AccessDeniedException", "nope", nil)},
			tags:    map[string][]*acm.Tag{"arn:ours": ourTag("cert-manager", "example")},
		}
		s := &ACMStore{}
		assert.Equal(t, "arn:ours", s.findAdoptableCertificate(stub, c))
	})
}

func TestSync_AdoptsInsteadOfImportingDuplicate(t *testing.T) {
	t.Setenv("ACM_ADOPT_EXISTING", "true")
	c := testCert(t, "cert-manager", "example")
	stub := &stubACM{
		summaries: []*acm.CertificateSummary{summary("arn:existing", "localhost", true, time.Now())},
		tags:      map[string][]*acm.Tag{"arn:existing": ourTag("cert-manager", "example")},
		newArn:    "arn:brand-new",
	}
	useStubACM(t, stub)

	s := &ACMStore{}
	updates, err := s.Sync(c)
	require.NoError(t, err)

	require.Len(t, stub.imports, 1)
	assert.Equal(t, "arn:existing", aws.StringValue(stub.imports[0].CertificateArn),
		"the import must update the adopted certificate in place, not create a second one")
	assert.Empty(t, stub.imports[0].Tags, "an adopted certificate is already tagged")
	// The recovered ARN has to be written back, or the next reconcile re-adopts.
	assert.Equal(t, map[string]string{"certificate-arn": "arn:existing"}, updates)
}

func TestSync_WithoutAdoption_ImportsNew(t *testing.T) {
	t.Setenv("ACM_ADOPT_EXISTING", "")
	c := testCert(t, "cert-manager", "example")
	stub := &stubACM{
		summaries: []*acm.CertificateSummary{summary("arn:existing", "localhost", true, time.Now())},
		tags:      map[string][]*acm.Tag{"arn:existing": ourTag("cert-manager", "example")},
		newArn:    "arn:brand-new",
	}
	useStubACM(t, stub)

	s := &ACMStore{}
	updates, err := s.Sync(c)
	require.NoError(t, err)

	assert.Zero(t, stub.listCalls, "adoption is opt-in; it must not call ACM when disabled")
	require.Len(t, stub.imports, 1)
	assert.Nil(t, stub.imports[0].CertificateArn)
	assert.Equal(t, map[string]string{"certificate-arn": "arn:brand-new"}, updates)
	assert.Len(t, stub.imports[0].Tags, 1, "a newly created certificate must be tagged for later adoption")
}

func TestSync_RecordedArnSkipsAdoption(t *testing.T) {
	t.Setenv("ACM_ADOPT_EXISTING", "true")
	c := testCert(t, "cert-manager", "example")
	stub := &stubACM{newArn: "arn:brand-new"}
	useStubACM(t, stub)

	s := &ACMStore{CertificateArn: "arn:known"}
	updates, err := s.Sync(c)
	require.NoError(t, err)

	assert.Zero(t, stub.listCalls, "a recorded ARN needs no lookup")
	require.Len(t, stub.imports, 1)
	assert.Equal(t, "arn:known", aws.StringValue(stub.imports[0].CertificateArn))
	assert.Nil(t, updates, "an unchanged ARN needs no annotation write-back")
}
