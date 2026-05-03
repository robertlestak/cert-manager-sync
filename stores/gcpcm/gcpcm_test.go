package gcpcm

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestIsGCPNotFound(t *testing.T) {
	assert.False(t, isGCPNotFound(nil))
	assert.False(t, isGCPNotFound(errors.New("plain")))
	assert.True(t, isGCPNotFound(status.Error(codes.NotFound, "missing")))
	assert.False(t, isGCPNotFound(status.Error(codes.Internal, "boom")))
}

func TestDelete_NoOpWhenCertificateNameMissing(t *testing.T) {
	// Sync never populated certificate-name → nothing was created → success.
	s := &GCPStore{}
	assert.NoError(t, s.Delete(context.Background()))
}
