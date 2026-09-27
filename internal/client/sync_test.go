package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cryptossh "golang.org/x/crypto/ssh"

	"github.com/mizuchilabs/kata/fsutil"

	nokkuv1 "github.com/nokku-sh/nk/internal/gen/nokku/v1"
	"github.com/nokku-sh/nk/internal/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nk/internal/paths"
	"github.com/nokku-sh/nk/internal/ssh"
	"github.com/nokku-sh/nk/internal/state"
)

// fakeBackend implements the two connect services the CLI syncs against:
// GetMyAccess for the snapshot and SignSSHCertificate for issuance.
type fakeBackend struct {
	nokkuv1connect.UnimplementedTargetServiceHandler
	nokkuv1connect.UnimplementedCertificateServiceHandler

	access    *nokkuv1.GetMyAccessResponse
	accessErr error
	test      *testing.T
	sign      func(t *testing.T, req *nokkuv1.SignSSHCertificateRequest) (*nokkuv1.SignSSHCertificateResponse, error)
}

func (f *fakeBackend) GetMyAccess(
	context.Context,
	*nokkuv1.GetMyAccessRequest,
) (*nokkuv1.GetMyAccessResponse, error) {
	return f.access, f.accessErr
}

func (f *fakeBackend) SignSSHCertificate(
	_ context.Context,
	req *nokkuv1.SignSSHCertificateRequest,
) (*nokkuv1.SignSSHCertificateResponse, error) {
	if f.sign == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, assert.AnError)
	}
	return f.sign(f.test, req)
}

// fakeCA signs test SSH certificates and exposes its public key in
// authorized_keys form, like the backend CAs do.
type fakeCA struct {
	signer cryptossh.Signer
	pubKey string
}

func newFakeCA(t *testing.T) *fakeCA {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := cryptossh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return &fakeCA{
		signer: signer,
		pubKey: string(cryptossh.MarshalAuthorizedKey(signer.PublicKey())),
	}
}

// signCert signs the given key into a user certificate valid from an hour
// ago until validFor from now.
func (f *fakeCA) signCert(t *testing.T, key cryptossh.PublicKey, validFor time.Duration) string {
	t.Helper()
	cert := &cryptossh.Certificate{
		Key:         key,
		CertType:    cryptossh.UserCert,
		ValidAfter:  uint64(time.Now().Add(-time.Hour).Unix()),
		ValidBefore: uint64(time.Now().Add(validFor).Unix()),
	}
	require.NoError(t, cert.SignCert(rand.Reader, f.signer))
	return string(cryptossh.MarshalAuthorizedKey(cert))
}

// signRequest signs the public key carried by an issuance request.
func (f *fakeCA) signRequest(t *testing.T, req *nokkuv1.SignSSHCertificateRequest) string {
	t.Helper()
	pub, _, _, _, err := cryptossh.ParseAuthorizedKey([]byte(req.GetPublicKey()))
	require.NoError(t, err, "issuance request carries an unparsable public key")
	return f.signCert(t, pub, time.Hour)
}

const (
	wsID     = "0199a0a0-0000-7000-8000-000000000001"
	caID     = "0199a0a0-0000-7000-8000-000000000002"
	targetID = "0199a0a0-0000-7000-8000-000000000003"
)

// setTestDirs points home at a fresh temp dir and creates what EnsurePaths
// would create at startup.
func setTestDirs(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	require.NoError(t, paths.EnsurePaths())
}

func newSyncTestClient(t *testing.T, backend *fakeBackend) *Client {
	t.Helper()
	backend.test = t
	mux := http.NewServeMux()
	targetPath, targetHandler := nokkuv1connect.NewTargetServiceHandler(backend)
	certPath, certHandler := nokkuv1connect.NewCertificateServiceHandler(backend)
	mux.Handle(targetPath, targetHandler)
	mux.Handle(certPath, certHandler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := &Client{State: &state.State{APIURL: srv.URL, SessionToken: "sess-token"}, httpc: srv.Client()}
	c.cc = nokkuv1connect.NewCertificateServiceClient(srv.Client(), srv.URL)
	c.tc = nokkuv1connect.NewTargetServiceClient(srv.Client(), srv.URL)
	return c
}

func accessResponse(caPubKey string) *nokkuv1.GetMyAccessResponse {
	return &nokkuv1.GetMyAccessResponse{
		Subject: &nokkuv1.GetMyAccessResponse_User{
			User: &nokkuv1.User{Id: new("user-1"), Name: new("alice")},
		},
		Workspaces: []*nokkuv1.WorkspaceAccess{{
			WorkspaceId:   new(wsID),
			WorkspaceName: new("production"),
			Targets: []*nokkuv1.Target{{
				Id:          new(targetID),
				Name:        new("prod"),
				WorkspaceId: new(wsID),
				CaId:        new(caID),
				Usernames:   []string{"alice"},
			}},
			CertificateAuthorities: []*nokkuv1.CertificateAuthority{{
				Id:          new(caID),
				WorkspaceId: new(wsID),
				Name:        new("Production CA"),
				PublicKey:   new(caPubKey),
			}},
		}},
	}
}

func TestSyncCommitsAccessSnapshot(t *testing.T) {
	setTestDirs(t)
	ca := newFakeCA(t)
	backend := &fakeBackend{access: accessResponse(ca.pubKey)}
	c := newSyncTestClient(t, backend)

	require.NoError(t, c.Sync(t.Context(), false))

	assert.Equal(t, "user-1", c.State.User.ID)
	assert.Equal(t, []state.Workspace{{ID: wsID, Name: "production"}}, c.State.Workspaces)
	require.Len(t, c.State.Targets, 1)
	assert.Equal(t, "prod", c.State.Targets[0].Name)
	require.Len(t, c.State.CAs, 1)
	assert.Equal(t, ca.pubKey, c.State.CAs[0].PublicKey)

	// The snapshot is committed to disk for offline use.
	assert.NotNil(t, state.Load().User)

	// And the derived SSH config was regenerated.
	content, err := os.ReadFile(paths.SSHConfigFile())
	require.NoError(t, err)
	assert.Contains(t, string(content), "Host prod\n")
}

func TestSyncUnauthenticatedNonInteractive(t *testing.T) {
	setTestDirs(t)
	backend := &fakeBackend{
		accessErr: connect.NewError(connect.CodeUnauthenticated, assert.AnError),
	}
	c := newSyncTestClient(t, backend)

	err := c.Sync(t.Context(), false)
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err),
		"a session rejection must surface as Unauthenticated so interactive callers re-login")
}

func TestSyncOrCacheFallsBackToCache(t *testing.T) {
	setTestDirs(t)

	st := &state.State{APIURL: "http://127.0.0.1:1", SessionToken: "sess-token"}
	st.Targets = []state.Target{{ID: "t-1", Name: "prod"}}
	st.User = &state.User{ID: "user-1"}
	require.NoError(t, st.Save())

	c := &Client{State: st}
	c.cc = nokkuv1connect.NewCertificateServiceClient(&http.Client{}, st.APIURL)
	c.tc = nokkuv1connect.NewTargetServiceClient(&http.Client{}, st.APIURL)
	err := c.SyncOrCache(t.Context(), false)
	require.NoError(t, err, "unreachable backend must fall back to cached data")
	assert.True(t, st.HasCachedData())
}

func TestSyncOrCacheWithoutCacheFails(t *testing.T) {
	setTestDirs(t)

	st := &state.State{APIURL: "http://127.0.0.1:1", SessionToken: "sess-token"}
	c := &Client{State: st}
	c.cc = nokkuv1connect.NewCertificateServiceClient(&http.Client{}, st.APIURL)
	c.tc = nokkuv1connect.NewTargetServiceClient(&http.Client{}, st.APIURL)
	err := c.SyncOrCache(t.Context(), false)
	assert.ErrorContains(t, err, "nothing is cached yet")
}

func TestEnsureCertFreshIsNoOp(t *testing.T) {
	setTestDirs(t)
	ca := newFakeCA(t)
	require.NoError(t, ssh.SetupKey(false))
	cliPub, err := ssh.GetPubKey()
	require.NoError(t, err)

	pub, _, _, _, err := cryptossh.ParseAuthorizedKey([]byte(cliPub))
	require.NoError(t, err)
	fresh := ca.signCert(t, pub, time.Hour)
	certPath := paths.SSHCertificate(caID)
	require.NoError(t, os.WriteFile(certPath, []byte(fresh), 0o600))

	c := &Client{State: &state.State{APIURL: "http://127.0.0.1:1", SessionToken: "sess-token"}}
	err = c.EnsureCert(t.Context(), state.CA{
		ID: caID, PublicKey: ca.pubKey,
	}, false)
	require.NoError(t, err, "a fresh certificate must not trigger a re-sign")
}

func TestEnsureCertSignsAndWritesCert(t *testing.T) {
	setTestDirs(t)
	ca := newFakeCA(t)
	require.NoError(t, ssh.SetupKey(false))

	backend := &fakeBackend{
		sign: func(t *testing.T, req *nokkuv1.SignSSHCertificateRequest) (*nokkuv1.SignSSHCertificateResponse, error) {
			assert.Equal(t, caID, req.GetCaId())
			assert.Equal(t, nokkuv1.SignSSHCertificateRequest_CERTIFICATE_TYPE_USER, req.GetType())
			return &nokkuv1.SignSSHCertificateResponse{
				CaId:              new(caID),
				SignedCertificate: new(ca.signRequest(t, req)),
			}, nil
		},
	}
	c := newSyncTestClient(t, backend)

	err := c.EnsureCert(t.Context(), state.CA{
		ID: caID, WorkspaceID: wsID, PublicKey: ca.pubKey,
	}, false)
	require.NoError(t, err)

	certPath := paths.SSHCertificate(caID)
	signed, err := os.ReadFile(certPath)
	require.NoError(t, err)
	require.NoError(t, ssh.CheckCert(signed, ca.pubKey, 0),
		"the written certificate must pass local validation")
}

func TestPrewarmCertsSignsMissingCerts(t *testing.T) {
	setTestDirs(t)
	ca := newFakeCA(t)
	require.NoError(t, ssh.SetupKey(false))

	backend := &fakeBackend{
		sign: func(t *testing.T, req *nokkuv1.SignSSHCertificateRequest) (*nokkuv1.SignSSHCertificateResponse, error) {
			return &nokkuv1.SignSSHCertificateResponse{
				CaId:              new(caID),
				SignedCertificate: new(ca.signRequest(t, req)),
			}, nil
		},
	}
	c := newSyncTestClient(t, backend)
	c.State.CAs = []state.CA{{ID: caID, WorkspaceID: wsID, PublicKey: ca.pubKey}}
	c.State.Targets = []state.Target{{ID: targetID, Name: "prod", CAID: caID}}

	c.PrewarmCerts(t.Context())

	certPath := paths.SSHCertificate(caID)
	assert.True(t, fsutil.FileExists(certPath),
		"prewarm must sign a certificate for the target's CA")
}
