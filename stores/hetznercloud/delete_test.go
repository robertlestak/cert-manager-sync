package hetznercloud

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHetznerDelete_NoOpWhenCertIdMissing(t *testing.T) {
	// Sync never populated cert-id → nothing was created → success.
	s := &HetznerCloudStore{ApiToken: "tok"}
	assert.NoError(t, s.Delete(context.Background()))
}

func TestHetznerDelete_RequiresCredentialsWhenCertIdSet(t *testing.T) {
	// cert-id present but no way to authenticate — must surface as error
	// so the operator retries and the user notices.
	s := &HetznerCloudStore{CertId: 5}
	err := s.Delete(context.Background())
	assert.Error(t, err)
}
