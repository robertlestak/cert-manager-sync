package vault

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupVaultEnv configures env vars so VaultStore.NewClient succeeds against
// the test httptest server: LOCAL+VAULT_TOKEN bypass the k8s auth login, and
// KUBE_TOKEN points at a real readable file (NewClient ReadFiles it).
func setupVaultEnv(t *testing.T) {
	t.Helper()
	t.Setenv("LOCAL", "1")
	t.Setenv("VAULT_TOKEN", "test")
	tokenPath := filepath.Join(t.TempDir(), "kube-token")
	require.NoError(t, os.WriteFile(tokenPath, []byte("dummy"), 0600))
	t.Setenv("KUBE_TOKEN", tokenPath)
}

func TestDeletePath(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "kv/foo", want: "kv/data/foo"},
		{in: "kv/foo/bar", want: "kv/data/foo/bar"},
		{in: "kv/data/foo", want: "kv/data/data/foo"}, // documents the existing path-mangling behavior
		{in: "single", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, c := range cases {
		got, err := deletePath(c.in)
		if c.wantErr {
			assert.Error(t, err, "input=%q", c.in)
			continue
		}
		require.NoError(t, err, "input=%q", c.in)
		assert.Equal(t, c.want, got)
	}
}

func TestIsVaultNotFound(t *testing.T) {
	assert.False(t, isVaultNotFound(nil))
	assert.False(t, isVaultNotFound(errors.New("plain error")))
	re := &api.ResponseError{StatusCode: 404}
	assert.True(t, isVaultNotFound(re))
	wrapped := &wrappedErr{err: re}
	assert.True(t, isVaultNotFound(wrapped))
	assert.False(t, isVaultNotFound(&api.ResponseError{StatusCode: 500}))
}

type wrappedErr struct{ err error }

func (w *wrappedErr) Error() string { return w.err.Error() }
func (w *wrappedErr) Unwrap() error { return w.err }

// fakeVault returns an httptest server that responds to DELETE on
// /v1/kv/data/* per the supplied status code.
func fakeVault(t *testing.T, status int, recorded *string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/kv/data/", func(w http.ResponseWriter, r *http.Request) {
		if recorded != nil {
			*recorded = r.Method + " " + r.URL.Path
		}
		w.WriteHeader(status)
	})
	return httptest.NewServer(mux)
}

func TestDelete_TreatsNotFoundAsSuccess(t *testing.T) {
	srv := fakeVault(t, http.StatusNotFound, nil)
	t.Cleanup(srv.Close)

	setupVaultEnv(t)

	s := &VaultStore{Addr: srv.URL, Path: "kv/foo/bar"}
	require.NoError(t, s.Delete(context.Background()))
}

func TestDelete_PropagatesNon404Errors(t *testing.T) {
	srv := fakeVault(t, http.StatusInternalServerError, nil)
	t.Cleanup(srv.Close)

	setupVaultEnv(t)

	s := &VaultStore{Addr: srv.URL, Path: "kv/foo/bar"}
	err := s.Delete(context.Background())
	require.Error(t, err)
}

func TestDelete_SuccessHitsExpectedPath(t *testing.T) {
	var got string
	srv := fakeVault(t, http.StatusNoContent, &got)
	t.Cleanup(srv.Close)

	setupVaultEnv(t)

	s := &VaultStore{Addr: srv.URL, Path: "kv/myapp/cert"}
	require.NoError(t, s.Delete(context.Background()))
	assert.Equal(t, "DELETE /v1/kv/data/myapp/cert", got)
}

func TestDelete_NoOpWhenPathMissing(t *testing.T) {
	// Sync never ran (no path configured) → nothing was written → success.
	s := &VaultStore{}
	assert.NoError(t, s.Delete(context.Background()))
}
