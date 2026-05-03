package filepath

import (
	"context"
	"os"
	fp "path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDelete_RemovesAllFiles(t *testing.T) {
	dir := t.TempDir()
	cert := fp.Join(dir, "tls.crt")
	key := fp.Join(dir, "tls.key")
	ca := fp.Join(dir, "ca.crt")
	for _, p := range []string{cert, key, ca} {
		require.NoError(t, os.WriteFile(p, []byte("data"), 0644))
	}

	s := &FilepathStore{Directory: dir}
	require.NoError(t, s.Delete(context.Background()))

	for _, p := range []string{cert, key, ca} {
		_, err := os.Stat(p)
		assert.True(t, os.IsNotExist(err), "%s should not exist", p)
	}
}

func TestDelete_IdempotentWhenMissing(t *testing.T) {
	dir := t.TempDir()
	s := &FilepathStore{Directory: dir}
	// No files exist; should succeed.
	assert.NoError(t, s.Delete(context.Background()))
}

func TestDelete_CustomFilenames(t *testing.T) {
	dir := t.TempDir()
	cert := fp.Join(dir, "my.crt")
	key := fp.Join(dir, "my.key")
	require.NoError(t, os.WriteFile(cert, []byte("x"), 0644))
	require.NoError(t, os.WriteFile(key, []byte("x"), 0644))

	s := &FilepathStore{Directory: dir, CertFile: "my.crt", KeyFile: "my.key", CAFile: "my.ca"}
	require.NoError(t, s.Delete(context.Background()))

	for _, p := range []string{cert, key} {
		_, err := os.Stat(p)
		assert.True(t, os.IsNotExist(err))
	}
}

func TestDelete_NoOpWhenDirectoryUnset(t *testing.T) {
	// An opt-in secret whose initial Sync failed before populating the
	// store config should not wedge on deletion. Missing config = nothing
	// was written = success.
	s := &FilepathStore{}
	assert.NoError(t, s.Delete(context.Background()))
}

func TestDelete_ErrorsOnPermissionDenied(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: chmod-based permission check is unreliable")
	}
	dir := t.TempDir()
	cert := fp.Join(dir, "tls.crt")
	require.NoError(t, os.WriteFile(cert, []byte("x"), 0644))
	// Make directory read-only so removal fails.
	require.NoError(t, os.Chmod(dir, 0500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	s := &FilepathStore{Directory: dir}
	err := s.Delete(context.Background())
	// On most systems removing a file from a read-only dir fails with EACCES.
	assert.Error(t, err)
}
