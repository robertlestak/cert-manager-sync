package acm

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/acm"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	log "github.com/sirupsen/logrus"
)

// Adoption closes the gap between "we have no recorded ARN" and "no certificate
// exists in ACM for this secret". Those are not the same thing: a reconcile that
// runs before the operator's write-back lands, a secret restored from backup, a
// GitOps tool that strips the annotation, or a cluster rebuilt against the same
// AWS account all leave a perfectly good ACM certificate behind with nothing
// pointing at it. Importing without an ARN in those cases mints a duplicate and
// orphans the original, which is never InUse, never cleaned up, and counts
// against the account's rolling 365-day import quota.
//
// Sync tags every certificate it creates with <operator>/secret-name =
// <namespace>/<secret>, so that tag is enough to find our own prior work.
//
// This is opt-in. Two clusters syncing same-named secrets into one AWS account
// produce identical tags, and adopting there would make them overwrite each
// other's certificates -- worse than the duplicates it prevents. Enable it only
// when the tag is unambiguous within the account.

// secretTagKey is the tag Sync stamps on every certificate it imports.
func secretTagKey() string {
	return state.OperatorName + "/secret-name"
}

// secretTagValue is the tag value identifying the source secret. It must match
// what certToACMInput writes, or adoption will never find anything.
func secretTagValue(c *tlssecret.Certificate) string {
	if c.Namespace != "" {
		return c.Namespace + "/" + c.SecretName
	}
	return c.SecretName
}

// adoptExisting reports whether this config opts in to adoption. The per-secret
// annotation wins over the cluster-wide ACM_ADOPT_EXISTING default.
func (s *ACMStore) adoptExisting() bool {
	if s.AdoptExisting != nil {
		return *s.AdoptExisting
	}
	return strings.EqualFold(os.Getenv("ACM_ADOPT_EXISTING"), "true")
}

// certDomains returns the CN and SANs of the leaf certificate, used to narrow
// the ACM listing before spending a ListTagsForCertificate call per candidate.
// An empty result means "could not tell", and every certificate is considered.
func certDomains(crt []byte) map[string]bool {
	block, _ := pem.Decode(crt)
	if block == nil {
		return nil
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	domains := make(map[string]bool)
	if parsed.Subject.CommonName != "" {
		domains[strings.ToLower(parsed.Subject.CommonName)] = true
	}
	for _, d := range parsed.DNSNames {
		domains[strings.ToLower(d)] = true
	}
	if len(domains) == 0 {
		return nil
	}
	return domains
}

// findAdoptableCertificate returns the ARN of an existing ACM certificate
// tagged for this secret, or "" if there is none.
//
// Every failure is non-fatal: adoption is an optimization, and falling back to
// a plain import reproduces the behavior of not having it. In particular a
// missing acm:ListCertificates or acm:ListTagsForCertificate permission logs
// and moves on rather than failing the sync.
func (s *ACMStore) findAdoptableCertificate(svc acmAPI, c *tlssecret.Certificate) string {
	wantValue := secretTagValue(c)
	l := log.WithFields(log.Fields{
		"action": "findAdoptableCertificate",
		"region": s.awsRegion(),
		"tag":    secretTagKey() + "=" + wantValue,
	})

	domains := certDomains(c.Certificate)
	var candidates []*acm.CertificateSummary
	err := svc.ListCertificatesPages(&acm.ListCertificatesInput{
		MaxItems: aws.Int64(100),
	}, func(page *acm.ListCertificatesOutput, _ bool) bool {
		for _, sum := range page.CertificateSummaryList {
			if sum == nil || sum.CertificateArn == nil {
				continue
			}
			// The tag is authoritative, but reading it costs an API call per
			// certificate. The domain is already in the summary, so use it to
			// skip the obvious non-matches first.
			if len(domains) > 0 && sum.DomainName != nil && !domains[strings.ToLower(*sum.DomainName)] {
				continue
			}
			candidates = append(candidates, sum)
		}
		return true
	})
	if err != nil {
		l.WithError(err).Warn("could not list ACM certificates; importing a new certificate instead")
		return ""
	}

	var matches []*acm.CertificateSummary
	for _, sum := range candidates {
		tags, err := svc.ListTagsForCertificate(&acm.ListTagsForCertificateInput{
			CertificateArn: sum.CertificateArn,
		})
		if err != nil {
			l.WithError(err).WithField("arn", *sum.CertificateArn).
				Warn("could not read certificate tags; skipping candidate")
			continue
		}
		for _, t := range tags.Tags {
			if t.Key != nil && *t.Key == secretTagKey() && t.Value != nil && *t.Value == wantValue {
				matches = append(matches, sum)
				break
			}
		}
	}

	if len(matches) == 0 {
		l.Debug("no existing certificate to adopt")
		return ""
	}

	// More than one match means duplicates already exist. Prefer the one
	// something is actually serving, then the most recently imported -- adopting
	// an orphan while a load balancer serves another would leave the live
	// certificate frozen at its current contents.
	sort.SliceStable(matches, func(i, j int) bool {
		iInUse, jInUse := aws.BoolValue(matches[i].InUse), aws.BoolValue(matches[j].InUse)
		if iInUse != jInUse {
			return iInUse
		}
		return importedAt(matches[i]).After(importedAt(matches[j]))
	})

	adopted := aws.StringValue(matches[0].CertificateArn)
	if len(matches) > 1 {
		var others []string
		for _, m := range matches[1:] {
			others = append(others, aws.StringValue(m.CertificateArn))
		}
		// Say so loudly: these are the orphans, and nothing here deletes them.
		l.WithFields(log.Fields{
			"adopted":    adopted,
			"duplicates": strings.Join(others, ","),
		}).Warn("multiple ACM certificates carry this secret's tag; adopting one, the rest need manual cleanup")
	} else {
		l.WithField("arn", adopted).Info("adopting existing ACM certificate")
	}
	return adopted
}

func importedAt(sum *acm.CertificateSummary) time.Time {
	if sum == nil || sum.ImportedAt == nil {
		return time.Time{}
	}
	return *sum.ImportedAt
}
