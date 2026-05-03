package cloudflare

import (
	"context"
	"errors"
	"testing"

	"github.com/cloudflare/cloudflare-go/v5"
	"github.com/stretchr/testify/assert"
)

func TestIsCloudflareNotFound(t *testing.T) {
	assert.False(t, isCloudflareNotFound(nil))
	assert.False(t, isCloudflareNotFound(errors.New("plain")))
	cfErr := &cloudflare.Error{StatusCode: 404}
	assert.True(t, isCloudflareNotFound(cfErr))
	other := &cloudflare.Error{StatusCode: 500}
	assert.False(t, isCloudflareNotFound(other))
}

func TestCloudflareDelete_NoOpWhenCertIdMissing(t *testing.T) {
	// Sync never populated cert-id → nothing was created → success.
	s := &CloudflareStore{ZoneId: "z", SecretName: "n"}
	assert.NoError(t, s.Delete(context.Background()))
}

func TestCloudflareDelete_RequiresOtherConfigWhenCertIdSet(t *testing.T) {
	// cert-id is set (Sync did succeed at some point), but other required
	// config has been removed. We must surface this as an error so the user
	// notices and either restores config or switches to retain.
	cases := []struct {
		name string
		s    *CloudflareStore
	}{
		{name: "missing zone id", s: &CloudflareStore{CertId: "c", SecretName: "n"}},
		{name: "missing secret name", s: &CloudflareStore{CertId: "c", ZoneId: "z"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.s.Delete(context.Background())
			assert.Error(t, err)
		})
	}
}
