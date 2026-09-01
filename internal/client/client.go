// Package client manages the connection to the Nokku backend.
package client

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"

	"golang.org/x/sync/errgroup"

	"github.com/nokku-sh/mon/dpop"
	"github.com/nokku-sh/mon/id"
	"github.com/nokku-sh/mon/tpm"

	"github.com/nokku-sh/nk/internal/fsutil"
	nokkuv1 "github.com/nokku-sh/nk/internal/gen/nokku/v1"
	"github.com/nokku-sh/nk/internal/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nk/internal/paths"
	"github.com/nokku-sh/nk/internal/ssh"
	"github.com/nokku-sh/nk/internal/state"
)

const (
	certRenewWindow = 15 * time.Minute
	syncTimeout     = 5 * time.Second
)

// SignerSalt namespaces the CLI's request-signing key derivation. It must
// stay distinct from the SSH identity salt so each purpose derives a
// distinct key from the same TPM. Exported for doctor, which reopens the
// identity read-only.
const SignerSalt = "nokku-cli"

type Client struct {
	State    *state.State
	proofer  *dpop.Proofer
	httpc    *http.Client
	dpopAuth *dpopAuth

	wc nokkuv1connect.WorkspaceServiceClient
	cc nokkuv1connect.CertificateServiceClient
	tc nokkuv1connect.TargetServiceClient
}

// New builds a client for s: it loads the machine signing identity, ensures
// the SSH key exists, and constructs the connectrpc clients. It performs no
// network I/O except the best-effort DPoP nonce bootstrap. Call Sync for
// backend access; it fails fast and falls back to cached data.
func New(ctx context.Context, s *state.State) (*Client, error) {
	c := &Client{State: s}

	// Headless (service-account) mode has no signing identity: the API key
	// is a plain bearer token with no DPoP binding. The CLI recovers from a
	// changed machine identity (relogin re-registers the new key), unlike
	// the daemon, whose enrollment is bound to its key.
	if !s.IsServiceAccount() {
		signer, err := tpm.NewSigner(tpm.SignerOptions{
			Salt:            []byte(SignerSalt),
			Store:           tpm.NewFileStore(paths.SignerStateFile()),
			MachineID:       id.MachineID,
			RequireTPM:      s.RequireTPM,
			RecoverIdentity: true,
		})
		if err != nil {
			return nil, err
		}
		c.proofer, err = dpop.NewProofer(signer, dpop.ProoferOptions{})
		if err != nil {
			return nil, err
		}
	}

	if err := ssh.SetupKey(s.RequireTPM); err != nil {
		return nil, err
	}
	if err := c.SetupClients(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// Sync refreshes the access snapshot from the backend and regenerates the
// derived SSH configuration. When interactive is false (used on paths that
// must never block, such as the SSH proxy), an expired or missing session is
// an error instead of a browser login flow. A server-side session rejection
// triggers exactly one re-login and retry when interactive.
func (c *Client) Sync(ctx context.Context, interactive bool) error {
	err := c.sync(ctx, interactive)
	if err == nil {
		return nil
	}
	if !interactive || connect.CodeOf(err) != connect.CodeUnauthenticated {
		return err
	}

	// The persisted session was rejected (revoked or expired early).
	// Re-authenticate once and retry; the retry is non-interactive so a
	// second rejection surfaces immediately.
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

	if err = c.State.Cache.Load(); err != nil {
		slog.Warn("failed to reload cache", "err", err)
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
		ca := c.State.GetCAByID(target.CAID)
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

// EnsureCert fetches a fresh SSH certificate for ca and writes it to disk.
// A valid (still-fresh) certificate is a no-op, so the proxy path stays
// offline-friendly. When re-signing is necessary it uses the existing
// session; with interactive set it will run the device login flow, otherwise
// it fails fast with ErrNotLoggedIn.
func (c *Client) EnsureCert(ctx context.Context, ca state.CA, interactive bool) error {
	if ssh.CertificateFresh(ca.ID, ca.PublicKey, certRenewWindow) {
		return nil // already signed, valid and under the current CA
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

	return fsutil.WriteFile(paths.SSHCertificate(res.GetCaId()), signedCert, 0o600)
}

// EnsureTargetCert signs the SSH certificate for a target's CA when needed.
func (c *Client) EnsureTargetCert(
	ctx context.Context,
	target *state.Target,
	interactive bool,
) error {
	ca := c.State.GetCAByID(target.CAID)
	if ca == nil {
		return fmt.Errorf("CA %q not found", target.CAID)
	}
	return c.EnsureCert(ctx, *ca, interactive)
}

// ListX509CAs returns all active X.509 CAs across the subject's
// workspaces. X.509 CAs are not linked to targets, so they are
// fetched separately from the access sync.
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

// SignX509Certificate signs a PEM-encoded PKCS#10 CSR with an X.509 CA
// and returns the signed certificate with its CA chain.
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
