package filepath

import (
	"context"
	"os"
	fp "path/filepath"
	"testing"

	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"

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

// mode returns the permission bits of path.
func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Mode().Perm()
}

// TestSync_PrivateKeyIsOwnerOnly locks in the file modes. The filepath store
// usually writes to a volume shared with another container; a world-readable
// tls.key hands the private key to every process that can see the mount, while
// the certificate and CA chain are public by design.
func TestSync_PrivateKeyIsOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	s := &FilepathStore{Directory: dir}
	_, err := s.Sync(&tlssecret.Certificate{
		SecretName:  "tls",
		Namespace:   "ns",
		Certificate: []byte("cert"),
		Key:         []byte("key"),
		Ca:          []byte("ca"),
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}

	if got := mode(t, fp.Join(dir, "tls.key")); got != 0600 {
		t.Errorf("tls.key mode = %04o, want 0600", got)
	}
	if got := mode(t, fp.Join(dir, "tls.crt")); got != 0644 {
		t.Errorf("tls.crt mode = %04o, want 0644", got)
	}
	if got := mode(t, fp.Join(dir, "ca.crt")); got != 0644 {
		t.Errorf("ca.crt mode = %04o, want 0644", got)
	}
}

// TestSync_TightensPreExistingKeyPermissions covers the upgrade path. A key
// written by an older version is already on disk at 0644, and os.WriteFile
// only applies its mode when it creates the file -- so without an explicit
// chmod the key would stay world-readable for the life of the volume.
func TestSync_TightensPreExistingKeyPermissions(t *testing.T) {
	dir := t.TempDir()
	keyPath := fp.Join(dir, "tls.key")
	if err := os.WriteFile(keyPath, []byte("stale"), 0644); err != nil {
		t.Fatalf("seed key: %v", err)
	}

	s := &FilepathStore{Directory: dir}
	if _, err := s.Sync(&tlssecret.Certificate{
		SecretName:  "tls",
		Namespace:   "ns",
		Certificate: []byte("cert"),
		Key:         []byte("key"),
	}); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	if got := mode(t, keyPath); got != 0600 {
		t.Errorf("pre-existing tls.key mode = %04o, want 0600", got)
	}
}
