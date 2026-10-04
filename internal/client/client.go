// Package client manages the connection to the Nokku backend.
package client

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/mizuchilabs/kata/buildinfo"
	"github.com/mizuchilabs/kata/fsutil"
	"github.com/nokku-sh/mon/dpopclient"
	"github.com/nokku-sh/mon/tpm"
	"google.golang.org/protobuf/types/known/durationpb"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nk/internal/paths"
	"github.com/nokku-sh/nk/internal/ssh"
	"github.com/nokku-sh/nk/internal/state"
)

const (
	syncTimeout = 5 * time.Second
	dialTimeout = 3 * time.Second
)

// signerSalt namespaces the CLI's DPoP key. Salt registry: mon/README.md.
const signerSalt = "nokku-cli"

type Client struct {
	State *state.State
	httpc *http.Client
	dpop  *dpopclient.Client

	ac nokkuv1connect.AuthServiceClient
	cc nokkuv1connect.CertificateServiceClient
	tc nokkuv1connect.TargetServiceClient
	dc nokkuv1connect.DaemonServiceClient
}

func New(s *state.State) (*Client, error) {
	if err := ssh.SetupKey(s.RequireTPM); err != nil {
		return nil, err
	}
	httpc, err := dpopclient.NewHTTPClient(s.Insecure, dialTimeout)
	if err != nil {
		return nil, err
	}
	c := &Client{State: s, httpc: httpc}

	var auth connect.Interceptor
	if s.IsServiceAccount() {
		auth = newBearerAuth(s.Token)
	} else {
		proofer, perr := dpopclient.NewProofer(
			[]byte(signerSalt),
			paths.SignerStateFile(),
			s.RequireTPM,
			tpm.RecreateIdentity,
		)
		if perr != nil {
			return nil, perr
		}
		c.dpop = dpopclient.New(proofer, httpc, func() string { return s.SessionToken }, dpopclient.Options{
			BaseURL:   s.APIURL,
			UserAgent: buildinfo.UserAgent("nk"),
		})
		auth = c.dpop
	}
	opts := connect.WithInterceptors(auth)
	c.ac = nokkuv1connect.NewAuthServiceClient(httpc, s.APIURL, opts)
	c.cc = nokkuv1connect.NewCertificateServiceClient(httpc, s.APIURL, opts)
	c.tc = nokkuv1connect.NewTargetServiceClient(httpc, s.APIURL, opts)
	c.dc = nokkuv1connect.NewDaemonServiceClient(httpc, s.APIURL, opts)
	return c, nil
}

// Reachable reports whether the backend answers a plain HTTP request within a
// short timeout. It is a diagnostic signal only.
func Reachable(ctx context.Context, st *state.State) bool {
	httpc, err := dpopclient.NewHTTPClient(st.Insecure, dialTimeout)
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	u := strings.TrimRight(st.APIURL, "/") + "/auth/device/nonce"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return true
}

// Sync refreshes the access snapshot and regenerates the ssh files. When
// interactive is false, a missing or rejected session is an error instead of
// a browser login.
func (c *Client) Sync(ctx context.Context, interactive bool) error {
	err := c.sync(ctx, interactive)
	if err == nil || !interactive || connect.CodeOf(err) != connect.CodeUnauthenticated {
		return err
	}
	// The stored session was rejected, log in once more.
	c.State.SessionToken, c.State.SessionExpiresAt = "", time.Time{}
	if err = c.ensureSession(ctx, true); err != nil {
		return err
	}
	return c.sync(ctx, false)
}

// SyncOrCache is Sync with a fallback to the cached snapshot, so ssh keeps
// working while the backend is down.
func (c *Client) SyncOrCache(ctx context.Context, interactive bool) error {
	err := c.Sync(ctx, interactive)
	if err == nil {
		return nil
	}
	if loadErr := c.State.LoadCache(); loadErr != nil || !c.State.HasCachedData() {
		return fmt.Errorf("cannot reach Nokku and nothing is cached yet: %w", err)
	}
	slog.Warn("cannot reach Nokku, using cached access", "err", err)
	c.State.MarkBackendDown()
	return nil
}

func (c *Client) sync(ctx context.Context, interactive bool) error {
	if err := c.ensureSession(ctx, interactive); err != nil {
		return err
	}
	syncCtx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()
	res, err := c.tc.GetMyAccess(syncCtx, &nokkuv1.GetMyAccessRequest{})
	if err != nil {
		return err
	}

	cache := state.FromAccess(res)
	cache.SyncedAt = time.Now()
	if err = ssh.CleanupCerts(cache.CAs); err != nil {
		return err
	}
	c.State.Cache = cache
	if err = c.State.Save(); err != nil {
		return err
	}
	return ssh.WriteConfigs(c.State)
}

// Logout revokes the device session on the backend. Best effort, the local
// state goes either way.
func (c *Client) Logout(ctx context.Context) {
	if c.State.IsServiceAccount() || c.State.SessionToken == "" {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()
	if _, err := c.ac.Logout(ctx, &nokkuv1.LogoutRequest{}); err != nil {
		slog.Debug("revoke session on the backend", "err", err)
	}
}

// EnsureCert makes sure a fresh certificate from ca is on disk, see
// ssh.CertFresh. When signing fails the one on disk stays, so ssh keeps
// working offline for as long as it is valid.
func (c *Client) EnsureCert(ctx context.Context, ca state.CA, interactive bool) error {
	if ssh.CertFresh(ca) {
		return nil
	}
	if err := c.ensureSession(ctx, interactive); err != nil {
		return err
	}
	pubKey, err := ssh.GetPubKey()
	if err != nil {
		return err
	}

	req := &nokkuv1.SignSSHCertificateRequest{
		WorkspaceId: new(ca.WorkspaceID),
		CaId:        new(ca.ID),
		Type:        nokkuv1.SignSSHCertificateRequest_CERTIFICATE_TYPE_USER.Enum(),
		PublicKey:   new(pubKey),
	}
	if c.State.TTL > 0 {
		req.Ttl = durationpb.New(c.State.TTL)
	}
	signCtx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()
	res, err := c.cc.SignSSHCertificate(signCtx, req)
	if err != nil {
		return err
	}

	signed := []byte(res.GetSignedCertificate())
	if err = ssh.CheckCert(signed, ca.PublicKey, 0); err != nil {
		return fmt.Errorf("backend returned an unusable certificate: %w", err)
	}
	return fsutil.WriteFile(paths.SSHCertificate(ca.ID), signed, 0o600)
}

// TargetPrincipals returns the subject UUIDs allowed per account on a manual
// target, with teams expanded.
func (c *Client) TargetPrincipals(ctx context.Context, t *state.Target) (map[string][]string, error) {
	res, err := c.tc.GetTargetPrincipals(ctx, &nokkuv1.GetTargetPrincipalsRequest{
		WorkspaceId: new(t.WorkspaceID),
		TargetId:    new(t.ID),
	})
	if err != nil {
		return nil, err
	}
	grants := make(map[string][]string, len(res.GetPrincipals()))
	for _, p := range res.GetPrincipals() {
		grants[p.GetUsername()] = p.GetIds()
	}
	return grants, nil
}

// ReportTarget reports a manual target's accounts, host key, and endpoints,
// which also stamps its last sync.
func (c *Client) ReportTarget(ctx context.Context, t *state.Target, accounts []string, hostKey string) error {
	_, err := c.tc.SyncTargetUsers(ctx, &nokkuv1.SyncTargetUsersRequest{
		WorkspaceId:   new(t.WorkspaceID),
		TargetId:      new(t.ID),
		Usernames:     accounts,
		HostPublicKey: new(hostKey),
		Endpoints:     t.Endpoints,
	})
	return err
}

// CreateTarget registers a manual target. An empty name asks the server to
// generate one.
func (c *Client) CreateTarget(ctx context.Context, t *state.Target) (*state.Target, error) {
	res, err := c.tc.CreateTarget(ctx, &nokkuv1.CreateTargetRequest{
		WorkspaceId:   new(t.WorkspaceID),
		CaId:          new(t.CAID),
		Name:          new(t.Name),
		HostPublicKey: new(t.HostPublicKey),
		Endpoints:     t.Endpoints,
	})
	if err != nil {
		return nil, err
	}
	created := state.MapTarget(res.GetTarget())
	created.WorkspaceID, created.CAID = t.WorkspaceID, t.CAID
	return &created, nil
}

func (c *Client) DeleteTarget(ctx context.Context, t *state.Target) error {
	_, err := c.tc.DeleteTarget(ctx, &nokkuv1.DeleteTargetRequest{
		WorkspaceId: new(t.WorkspaceID),
		Id:          new(t.ID),
	})
	return err
}

// ListX509CAs returns the active X.509 CAs across the workspaces. They are
// not linked to targets, so they are fetched separately from the access sync.
func (c *Client) ListX509CAs(ctx context.Context) ([]*nokkuv1.CertificateAuthority, error) {
	var out []*nokkuv1.CertificateAuthority
	for _, w := range c.State.Workspaces {
		res, err := c.cc.ListCertificateAuthorities(ctx, &nokkuv1.ListCertificateAuthoritiesRequest{
			WorkspaceId: new(w.ID),
		})
		if err != nil {
			return nil, err
		}
		for _, ca := range res.GetCertificateAuthorities() {
			if ca.GetAuthorityType() == nokkuv1.AuthorityType_AUTHORITY_TYPE_X509 && ca.GetIsActive() {
				out = append(out, ca)
			}
		}
	}
	return out, nil
}

func (c *Client) SignX509Certificate(
	ctx context.Context,
	ca *nokkuv1.CertificateAuthority,
	csrPEM string,
	usage nokkuv1.SignX509CertificateRequest_X509Usage,
) (*nokkuv1.SignX509CertificateResponse, error) {
	req := &nokkuv1.SignX509CertificateRequest{
		WorkspaceId: new(ca.GetWorkspaceId()),
		CaId:        new(ca.GetId()),
		Csr:         new(csrPEM),
		Usage:       usage.Enum(),
	}
	if c.State.TTL > 0 {
		req.Ttl = durationpb.New(c.State.TTL)
	}
	return c.cc.SignX509Certificate(ctx, req)
}
