package cloudflare

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/cloudflare-go/v5"
	"github.com/cloudflare/cloudflare-go/v5/option"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	log "github.com/sirupsen/logrus"
)

const testZone = "zone123"

// testLeaf returns a self-signed leaf certificate and its key, both PEM encoded.
func testLeaf(t *testing.T, cn string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// fakeCloudflare is a minimal Cloudflare API for the origin_tls_client_auth
// endpoints. Certificates are stored by ID; uploading one already stored fails
// with error 1406 like the real API.
type fakeCloudflare struct {
	mu        sync.Mutex
	certs     map[string]string // id -> PEM
	nextID    int
	uploads   int
	deleted   []string
	associate []map[string]any
}

func newFakeCloudflare(t *testing.T) (*fakeCloudflare, *cloudflare.Client) {
	t.Helper()
	f := &fakeCloudflare{certs: map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	client := cloudflare.NewClient(
		option.WithBaseURL(srv.URL+"/"),
		option.WithAPIToken("test"),
		option.WithMaxRetries(0),
	)
	return f, client
}

func (f *fakeCloudflare) add(pemCert string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	id := "cert-" + string(rune('a'+f.nextID-1))
	f.certs[id] = pemCert
	return id
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func ok(w http.ResponseWriter, result any) {
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": result})
}

func fail(w http.ResponseWriter, status int, code int, msg string) {
	writeJSON(w, status, map[string]any{"success": false, "errors": []any{map[string]any{"code": code, "message": msg}}, "messages": []any{}, "result": nil})
}

func (f *fakeCloudflare) serve(w http.ResponseWriter, r *http.Request) {
	prefix := "/zones/" + testZone + "/origin_tls_client_auth"
	path := strings.TrimPrefix(r.URL.Path, prefix)
	if path == r.URL.Path {
		fail(w, http.StatusNotFound, 7003, "unknown zone")
		return
	}
	// Zone-level and per-hostname certificates share the fake store.
	certPath := strings.TrimPrefix(path, "/hostnames")
	switch {
	case r.Method == http.MethodPut && path == "/hostnames":
		var body map[string]any
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		f.mu.Lock()
		f.associate = append(f.associate, body)
		f.mu.Unlock()
		ok(w, []any{})
	case r.Method == http.MethodPost && (certPath == "" || certPath == "/certificates"):
		var body struct {
			Certificate string `json:"certificate"`
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		f.mu.Lock()
		for _, c := range f.certs {
			if c == body.Certificate {
				f.mu.Unlock()
				fail(w, http.StatusBadRequest, 1406, "This certificate already exists for this zone.")
				return
			}
		}
		f.uploads++
		f.mu.Unlock()
		id := f.add(body.Certificate)
		ok(w, map[string]any{"id": id, "certificate": body.Certificate})
	case r.Method == http.MethodGet && (certPath == "" || certPath == "/certificates"):
		f.mu.Lock()
		list := []any{}
		for id, c := range f.certs {
			list = append(list, map[string]any{"id": id, "certificate": c})
		}
		f.mu.Unlock()
		ok(w, list)
	case r.Method == http.MethodGet || r.Method == http.MethodDelete:
		id := certPath[strings.LastIndex(certPath, "/")+1:]
		f.mu.Lock()
		c, found := f.certs[id]
		if found && r.Method == http.MethodDelete {
			delete(f.certs, id)
			f.deleted = append(f.deleted, id)
		}
		f.mu.Unlock()
		if !found {
			fail(w, http.StatusNotFound, 1404, "not found")
			return
		}
		ok(w, map[string]any{"id": id, "certificate": c})
	default:
		fail(w, http.StatusMethodNotAllowed, 1000, "unexpected "+r.Method+" "+r.URL.Path)
	}
}

func associatedCertIDs(t *testing.T, body map[string]any) map[string]string {
	t.Helper()
	out := map[string]string{}
	cfg, _ := body["config"].([]any)
	for _, c := range cfg {
		m := c.(map[string]any)
		out[m["hostname"].(string)] = m["cert_id"].(string)
	}
	return out
}

func hostnameStore(certID string, hostnames ...string) *CloudflareStore {
	return &CloudflareStore{ZoneId: testZone, CertId: certID, Mode: ModeOriginPullHostname, Hostnames: hostnames}
}

// A sync triggered by a new hostname (same certificate, cert-id recorded)
// must not upload again and must associate every hostname.
func TestSyncOriginPullHostname_ReusesUploadedCertificate(t *testing.T) {
	f, client := newFakeCloudflare(t)
	crt, key := testLeaf(t, "client")
	id := f.add(string(crt))

	s := hostnameStore(id, "a.example.com", "b.example.com")
	if err := s.syncOriginPullHostname(context.Background(), client, &tlssecret.Certificate{Certificate: crt, Key: key}, log.WithField("test", t.Name())); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if f.uploads != 0 {
		t.Errorf("uploads = %d, want 0", f.uploads)
	}
	if s.CertId != id {
		t.Errorf("CertId = %q, want %q", s.CertId, id)
	}
	if len(f.associate) != 1 {
		t.Fatalf("associations = %d, want 1", len(f.associate))
	}
	got := associatedCertIDs(t, f.associate[0])
	if got["a.example.com"] != id || got["b.example.com"] != id {
		t.Errorf("associated %v, want both hostnames on %s", got, id)
	}
	if len(f.deleted) != 0 {
		t.Errorf("deleted %v, want nothing", f.deleted)
	}
}

// Cloudflare already has the certificate but the secret has no cert-id: the
// 1406 answer must resolve to the existing certificate.
func TestSyncOriginPullHostname_RecoversFromCertificateExists(t *testing.T) {
	f, client := newFakeCloudflare(t)
	crt, key := testLeaf(t, "client")
	id := f.add(string(crt))

	s := hostnameStore("", "a.example.com")
	if err := s.syncOriginPullHostname(context.Background(), client, &tlssecret.Certificate{Certificate: crt, Key: key}, log.WithField("test", t.Name())); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if s.CertId != id {
		t.Errorf("CertId = %q, want %q", s.CertId, id)
	}
	if got := associatedCertIDs(t, f.associate[0]); got["a.example.com"] != id {
		t.Errorf("associated %v, want a.example.com on %s", got, id)
	}
}

// A renewal (new certificate) uploads it, associates it, then drops the old one.
func TestSyncOriginPullHostname_RenewalReplacesCertificate(t *testing.T) {
	f, client := newFakeCloudflare(t)
	oldCrt, _ := testLeaf(t, "client")
	oldID := f.add(string(oldCrt))
	crt, key := testLeaf(t, "client")

	s := hostnameStore(oldID, "a.example.com")
	if err := s.syncOriginPullHostname(context.Background(), client, &tlssecret.Certificate{Certificate: crt, Key: key}, log.WithField("test", t.Name())); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if f.uploads != 1 {
		t.Errorf("uploads = %d, want 1", f.uploads)
	}
	if s.CertId == oldID || s.CertId == "" {
		t.Errorf("CertId = %q, want a new id", s.CertId)
	}
	if got := associatedCertIDs(t, f.associate[0]); got["a.example.com"] != s.CertId {
		t.Errorf("associated %v, want a.example.com on %s", got, s.CertId)
	}
	if len(f.deleted) != 1 || f.deleted[0] != oldID {
		t.Errorf("deleted %v, want [%s]", f.deleted, oldID)
	}
}

// The recorded cert-id is gone from Cloudflare: upload again.
func TestSyncOriginPullHostname_UploadsWhenRecordedCertificateIsGone(t *testing.T) {
	f, client := newFakeCloudflare(t)
	crt, key := testLeaf(t, "client")

	s := hostnameStore("cert-missing", "a.example.com")
	if err := s.syncOriginPullHostname(context.Background(), client, &tlssecret.Certificate{Certificate: crt, Key: key}, log.WithField("test", t.Name())); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if f.uploads != 1 {
		t.Errorf("uploads = %d, want 1", f.uploads)
	}
}

// Zone-level mode: same certificate already uploaded, nothing to do.
func TestSyncOriginPull_ReusesUploadedCertificate(t *testing.T) {
	f, client := newFakeCloudflare(t)
	crt, key := testLeaf(t, "client")
	id := f.add(string(crt))

	s := &CloudflareStore{ZoneId: testZone, CertId: id, Mode: ModeOriginPull}
	if err := s.syncOriginPull(context.Background(), client, &tlssecret.Certificate{Certificate: crt, Key: key}, log.WithField("test", t.Name())); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if f.uploads != 0 || s.CertId != id || len(f.deleted) != 0 {
		t.Errorf("uploads=%d CertId=%q deleted=%v, want 0, %q, none", f.uploads, s.CertId, f.deleted, id)
	}
}

// Zone-level mode: 1406 without a recorded cert-id resolves to the existing one.
func TestSyncOriginPull_RecoversFromCertificateExists(t *testing.T) {
	f, client := newFakeCloudflare(t)
	crt, key := testLeaf(t, "client")
	id := f.add(string(crt))

	s := &CloudflareStore{ZoneId: testZone, Mode: ModeOriginPull}
	if err := s.syncOriginPull(context.Background(), client, &tlssecret.Certificate{Certificate: crt, Key: key}, log.WithField("test", t.Name())); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if s.CertId != id {
		t.Errorf("CertId = %q, want %q", s.CertId, id)
	}
}

func TestSameCertificate(t *testing.T) {
	a, _ := testLeaf(t, "a")
	b, _ := testLeaf(t, "b")
	// Re-encoded PEM (CRLF, trailing newline dropped) is still the same certificate.
	reencoded := strings.TrimSpace(strings.ReplaceAll(string(a), "\n", "\r\n"))
	if !sameCertificate(reencoded, a) {
		t.Error("re-encoded PEM should match")
	}
	if sameCertificate(string(b), a) {
		t.Error("different certificates should not match")
	}
	if sameCertificate("", a) || sameCertificate("garbage", a) {
		t.Error("empty or invalid PEM should not match")
	}
}
