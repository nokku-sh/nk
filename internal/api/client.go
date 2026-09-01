// Package api manages the connection to the Nokku API.
package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/grpchealth"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/nokku-sh/nk/internal/dpop"
	nokkuv1 "github.com/nokku-sh/nk/internal/gen/nokku/v1"
	"github.com/nokku-sh/nk/internal/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nk/internal/ssh"
	"github.com/nokku-sh/nk/internal/state"
	"github.com/nokku-sh/nk/internal/tpm"
	"github.com/nokku-sh/nk/internal/util"
)

// certRenewWindow is how close to expiry a cached certificate may get before
// it is re-signed. Signing while the backend is still reachable keeps the
// cert fresh for offline use later.
const certRenewWindow = 15 * time.Minute

type Client struct {
	State   *state.State
	proofer *dpop.Proofer
	httpc   *http.Client

	uc nokkuv1connect.UtilServiceClient
	wc nokkuv1connect.WorkspaceServiceClient
	cc nokkuv1connect.CertificateServiceClient
	tc nokkuv1connect.TargetServiceClient
}

// Connect builds a client from s and refreshes it, falling back to cached
// data when the backend is unreachable.
func Connect(ctx context.Context, s *state.State) (*Client, error) {
	c, err := New(ctx, s)
	if err != nil {
		return nil, err
	}
	if err = c.Refresh(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// New builds a client for s: it loads the machine signing identity, ensures
// the SSH key exists, and constructs the connectrpc clients. The only
// network I/O is the DPoP nonce bootstrap; call Refresh to authenticate and
// sync.
func New(ctx context.Context, s *state.State) (*Client, error) {
	c := &Client{State: s}

	// Headless (service-account) mode has no signing identity: the API key
	// is a plain bearer token with no DPoP binding. Interactive mode creates
	// the machine key that binds the device session.
	if !s.IsServiceAccount() {
		signer, err := tpm.New(util.ConfigPath(), s.RequireTPM)
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

// Refresh performs a full online refresh, or falls back to cached data when
// the backend is unreachable or the refresh fails.
func (c *Client) Refresh(ctx context.Context) error {
	if !Healthy(ctx, c.State) {
		if !c.State.HasCachedData() {
			return fmt.Errorf("backend unreachable and no cached data available")
		}
		return nil
	}

	if err := c.refresh(ctx); err != nil {
		if !c.State.HasCachedData() {
			return err
		}
		// A refresh may have partially mutated in-memory state, but nothing
		// is persisted until it succeeds. Reload the last-good snapshot from
		// disk so the fallback serves a consistent view.
		if loadErr := c.State.Cache.Load(); loadErr != nil {
			slog.Warn("failed to reload cache", "err", loadErr)
		}
		slog.Warn("online refresh failed, continuing with cached data", "err", err)
	}
	return nil
}

// Healthy reports whether the backend is reachable.
func Healthy(ctx context.Context, st *state.State) bool {
	httpc, err := newHTTPClient(st.Insecure)
	if err != nil {
		return false
	}
	hc := grpchealth.NewClient(httpc, st.APIURL)

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	res, err := hc.Check(ctx, &grpchealth.CheckRequest{})
	return err == nil && res.Status == grpchealth.StatusServing
}

// refresh performs the full online refresh: authenticate, sync, commit the
// snapshot, and regenerate the SSH configuration.
func (c *Client) refresh(ctx context.Context) error {
	if err := c.login(ctx); err != nil {
		return err
	}
	if err := c.syncAll(ctx); err != nil {
		return err
	}

	c.ensureUserCerts(ctx)

	// Commit the fresh snapshot before deriving artifacts from it. Only a
	// fully successful sync reaches this point, so the on-disk cache is
	// never left half-updated.
	if err := c.State.Save(); err != nil {
		return err
	}

	if err := ssh.GenerateSSHConfig(c.State); err != nil {
		return err
	}
	if err := ssh.GenerateKnownHosts(c.State); err != nil {
		return err
	}
	// The generated config is only reachable through the user's include
	// directive; wire it up now that we have written a managed config.
	return util.EnsureSSHConfigInclude()
}

// ensureUserCerts signs every user SSH certificate that is missing or near
// expiry. It is best-effort: failures are logged and the previously cached
// certificate remains in place, so an offline connection can still fall back
// to it.
func (c *Client) ensureUserCerts(ctx context.Context) {
	for _, target := range c.State.Targets {
		ca := c.State.GetCAByID(target.CAID)
		if ca == nil {
			continue
		}
		if err := c.SignSSHCertificate(ctx, *ca); err != nil {
			slog.Warn("certificate signing failed", "target", target.Name, "err", err)
		}
	}
}

// SignTarget signs the SSH certificate for a target's CA.
func (c *Client) SignTarget(ctx context.Context, target *state.Target) error {
	ca := c.State.GetCAByID(target.CAID)
	if ca == nil {
		return fmt.Errorf("CA %q not found", target.CAID)
	}
	return c.SignSSHCertificate(ctx, *ca)
}

// SignSSHCertificate fetches a fresh SSH certificate for ca and writes it
// to disk. A valid (still-fresh) certificate is a no-op, so the proxy path
// stays offline-friendly. Only when re-signing is necessary does it ensure a
// session (device login if needed) and contact the backend.
func (c *Client) SignSSHCertificate(ctx context.Context, ca state.CA) error {
	if ssh.CertificateFresh(ca.ID, ca.PublicKey, certRenewWindow) {
		return nil // already signed, valid and under the current CA
	}
	if err := c.login(ctx); err != nil {
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

	return util.WriteFile(util.SSHCertificate(res.GetCaId()), signedCert, 0o600)
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
