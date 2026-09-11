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
	"github.com/nokku-sh/mon/dpopclient"
	"github.com/nokku-sh/mon/fsutil"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/durationpb"

	nokkuv1 "github.com/nokku-sh/nk/internal/gen/nokku/v1"
	"github.com/nokku-sh/nk/internal/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nk/internal/paths"
	"github.com/nokku-sh/nk/internal/ssh"
	"github.com/nokku-sh/nk/internal/state"
)

const (
	certRenewWindow = 15 * time.Minute
	syncTimeout     = 5 * time.Second
	dialTimeout     = 3 * time.Second
)

type Client struct {
	State *state.State
	httpc *http.Client
	dpop  *dpopclient.Client

	cc nokkuv1connect.CertificateServiceClient
	tc nokkuv1connect.TargetServiceClient
	dc nokkuv1connect.DaemonServiceClient
}

func New(s *state.State) (*Client, error) {
	c := &Client{State: s}

	if err := ssh.SetupKey(s.RequireTPM); err != nil {
		return nil, err
	}
	if err := c.setupClients(); err != nil {
		return nil, err
	}
	return c, nil
}

// setupClients builds the shared HTTP client and the connect service clients.
func (c *Client) setupClients() error {
	httpc, err := dpopclient.NewHTTPClient(c.State.Insecure, dialTimeout)
	if err != nil {
		return err
	}
	c.httpc = httpc

	interceptors := []connect.Interceptor{withRetry()}
	if c.State.IsServiceAccount() {
		interceptors = append(interceptors, newBearerAuth(c.State.Token))
	} else {
		proofer, perr := newProofer(c.State)
		if perr != nil {
			return perr
		}
		c.dpop = dpopclient.New(
			proofer,
			httpc,
			func() string { return c.State.SessionToken },
			dpopclient.Options{
				BaseURL:   c.State.APIURL,
				UserAgent: buildinfo.UserAgent("nk"),
			},
		)
		interceptors = append(interceptors, c.dpop)
	}
	opts := connect.WithInterceptors(interceptors...)

	c.cc = nokkuv1connect.NewCertificateServiceClient(httpc, c.State.APIURL, opts)
	c.tc = nokkuv1connect.NewTargetServiceClient(httpc, c.State.APIURL, opts)
	c.dc = nokkuv1connect.NewDaemonServiceClient(httpc, c.State.APIURL, opts)
	return nil
}

// Reachable reports whether the backend answers a plain HTTP request within a
// short timeout. It is a diagnostic signal only, commands never probe before
// acting.
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

// Sync refreshes the access snapshot from the backend and regenerates the
// derived SSH configuration. When interactive is false, an expired or missing
// session is an error instead of a browser login flow.
func (c *Client) Sync(ctx context.Context, interactive bool) error {
	err := c.sync(ctx, interactive)
	if err == nil {
		return nil
	}
	if !interactive || connect.CodeOf(err) != connect.CodeUnauthenticated {
		return err
	}

	// The persisted session was rejected, so re-authenticate once. The retry
	// is non-interactive so a second rejection surfaces immediately.
	c.State.SessionToken = ""
	c.State.SessionExpiresAt = time.Time{}
	if err = c.ensureSession(ctx, true); err != nil {
		return err
	}
	return c.sync(ctx, false)
}

// SyncOrCache refreshes state, falling back to the cached snapshot whenever
// the backend is unreachable or the sync fails.
func (c *Client) SyncOrCache(ctx context.Context, interactive bool) error {
	err := c.Sync(ctx, interactive)
	if err == nil {
		return nil
	}
	if !c.State.HasCachedData() {
		return fmt.Errorf("backend unreachable and no cached data available: %w", err)
	}

	if loadErr := c.State.Cache.Load(); loadErr != nil {
		slog.Warn("failed to reload cache", "err", loadErr)
	}
	slog.Warn("online sync failed, continuing with cached data", "err", err)
	return nil
}

// sync authenticates (if needed), pulls the access snapshot, and commits it
// with the derived SSH configuration.
func (c *Client) sync(ctx context.Context, interactive bool) error {
	if err := c.ensureSession(ctx, interactive); err != nil {
		return err
	}

	syncCtx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()

	if err := c.syncAccess(syncCtx); err != nil {
		return err
	}

	if err := ssh.GenerateSSHConfig(c.State); err != nil {
		return err
	}
	if err := ssh.GenerateKnownHosts(c.State); err != nil {
		return err
	}
	return paths.EnsureSSHConfigInclude()
}

func (c *Client) syncAccess(ctx context.Context) error {
	res, err := c.tc.GetMyAccess(ctx, &nokkuv1.GetMyAccessRequest{})
	if err != nil {
		return err
	}

	st := c.State
	switch subject := res.GetSubject().(type) {
	case *nokkuv1.GetMyAccessResponse_User:
		st.User = state.MapUser(subject.User)
		st.ServiceAccount = nil
	case *nokkuv1.GetMyAccessResponse_ServiceAccount:
		st.ServiceAccount = state.MapServiceAccount(subject.ServiceAccount)
		st.User = nil
	}

	workspaces := make([]state.Workspace, 0, len(res.GetWorkspaces()))
	targets := make([]state.Target, 0)
	cas := make([]state.CA, 0)
	for _, wa := range res.GetWorkspaces() {
		workspaces = append(workspaces, state.Workspace{
			ID:   wa.GetWorkspaceId(),
			Name: wa.GetWorkspaceName(),
		})
		targets = append(targets, state.MapTargets(wa.GetTargets())...)
		cas = append(cas, state.MapCAs(wa.GetCertificateAuthorities())...)
	}

	// prune the removed ones before the snapshot is committed
	if err = ssh.CleanupCerts(cas); err != nil {
		return err
	}

	st.Workspaces = workspaces
	st.Targets = targets
	st.CAs = cas
	return c.State.Save()
}

// PrewarmCerts signs every user SSH certificate that is missing or near
// expiry, in parallel.
func (c *Client) PrewarmCerts(ctx context.Context) {
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(4)
	for _, target := range c.State.Targets {
		ca := c.State.CAByID(target.CAID)
		if ca == nil {
			continue
		}
		g.Go(func() error {
			if err := c.EnsureCert(ctx, *ca, false); err != nil {
				slog.Warn("certificate signing failed", "target", target.Name, "err", err)
			}
			return nil
		})
	}
	_ = g.Wait()
}

// EnsureCert fetches a fresh SSH certificate for ca and writes it to disk. A
// valid certificate is a no-op, so the proxy path stays offline-friendly.
func (c *Client) EnsureCert(ctx context.Context, ca state.CA, interactive bool) error {
	if ssh.CertificateFresh(ca.ID, ca.PublicKey, certRenewWindow) {
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
		WorkspaceId: &ca.WorkspaceID,
		Type:        nokkuv1.SignSSHCertificateRequest_CERTIFICATE_TYPE_USER.Enum(),
		PublicKey:   &pubKey,
		CaId:        &ca.ID,
	}

	if c.State.TTL != 0 && c.State.TTL >= ca.UserDefaultTTL &&
		c.State.TTL <= ca.UserMaxTTL {
		req.Ttl = durationpb.New(c.State.TTL)
	}

	res, err := c.cc.SignSSHCertificate(ctx, req)
	if err != nil {
		return err
	}

	signedCert := []byte(res.GetSignedCertificate())
	if err = ssh.VerifyCertificate(signedCert); err != nil {
		return err
	}

	// Trust the id we requested, not the one echoed back.
	certPath, err := paths.SSHCertificate(ca.ID)
	if err != nil {
		return err
	}
	return fsutil.WriteFile(certPath, signedCert, 0o600)
}

func (c *Client) EnsureTargetCert(
	ctx context.Context,
	target *state.Target,
	interactive bool,
) error {
	ca := c.State.CAByID(target.CAID)
	if ca == nil {
		return fmt.Errorf("CA %q not found", target.CAID)
	}
	return c.EnsureCert(ctx, *ca, interactive)
}

// GetTargetPrincipals returns the principals a daemonless target's sshd
// authorizes, with team memberships expanded.
func (c *Client) GetTargetPrincipals(
	ctx context.Context,
	workspaceID, targetID string,
) ([]*nokkuv1.PrincipalUsers, error) {
	res, err := c.tc.GetTargetPrincipals(ctx, &nokkuv1.GetTargetPrincipalsRequest{
		WorkspaceId: new(workspaceID),
		TargetId:    new(targetID),
	})
	if err != nil {
		return nil, err
	}
	return res.GetPrincipals(), nil
}

// SyncTargetUsers reports a daemonless target's local accounts, host key, and
// endpoints to the backend.
func (c *Client) SyncTargetUsers(
	ctx context.Context,
	workspaceID, targetID string,
	usernames []string,
	hostPublicKey string,
	endpoints []string,
) error {
	_, err := c.tc.SyncTargetUsers(ctx, &nokkuv1.SyncTargetUsersRequest{
		WorkspaceId:   new(workspaceID),
		TargetId:      new(targetID),
		Usernames:     usernames,
		HostPublicKey: new(hostPublicKey),
		Endpoints:     endpoints,
	})
	return err
}

// CreateTarget registers a target. An empty name asks the server to generate
// one.
func (c *Client) CreateTarget(
	ctx context.Context,
	workspaceID, caID, name, hostPublicKey string,
	endpoints []string,
) (*nokkuv1.Target, error) {
	res, err := c.tc.CreateTarget(ctx, &nokkuv1.CreateTargetRequest{
		WorkspaceId:   new(workspaceID),
		CaId:          new(caID),
		Name:          new(name),
		HostPublicKey: new(hostPublicKey),
		Endpoints:     endpoints,
	})
	if err != nil {
		return nil, err
	}
	return res.GetTarget(), nil
}

// ListX509CAs returns the active X.509 CAs across the workspaces. They are
// not linked to targets, so they are fetched separately from the access sync.
func (c *Client) ListX509CAs(ctx context.Context) ([]*nokkuv1.CertificateAuthority, error) {
	var out []*nokkuv1.CertificateAuthority
	for _, w := range c.State.Workspaces {
		res, err := c.cc.ListCertificateAuthorities(ctx, &nokkuv1.ListCertificateAuthoritiesRequest{
			WorkspaceId: &w.ID,
		})
		if err != nil {
			return nil, err
		}
		for _, ca := range res.GetCertificateAuthorities() {
			if ca.GetAuthorityType() == nokkuv1.AuthorityType_AUTHORITY_TYPE_X509 &&
				ca.GetIsActive() {
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
	ttl time.Duration,
) (*nokkuv1.SignX509CertificateResponse, error) {
	req := &nokkuv1.SignX509CertificateRequest{
		WorkspaceId: new(ca.GetWorkspaceId()),
		CaId:        new(ca.GetId()),
		Csr:         &csrPEM,
		Usage:       usage.Enum(),
	}
	if ttl > 0 {
		req.Ttl = durationpb.New(ttl)
	}
	return c.cc.SignX509Certificate(ctx, req)
}
