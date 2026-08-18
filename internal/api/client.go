// Package api manages the connection to the Nokku API.
package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/grpchealth"
	"github.com/mizuchilabs/kagi/dpop"
	"github.com/urfave/cli/v3"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/durationpb"

	nokkuv1 "github.com/nokku-sh/nk/internal/gen/nokku/v1"
	"github.com/nokku-sh/nk/internal/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nk/internal/ssh"
	"github.com/nokku-sh/nk/internal/state"
	"github.com/nokku-sh/nk/internal/tpm"
	"github.com/nokku-sh/nk/internal/util"
)

type Client struct {
	State   *state.State
	signer  tpm.Signer
	proofer *dpop.Proofer
	httpc   *http.Client

	ac nokkuv1connect.AuthServiceClient
	uc nokkuv1connect.UserServiceClient
	wc nokkuv1connect.WorkspaceServiceClient
	cc nokkuv1connect.CertificateServiceClient
	tc nokkuv1connect.TargetServiceClient
}

// New creates a client, probes the backend, and either does a full online
// refresh or falls back to cached data when offline.
func New(ctx context.Context, cmd *cli.Command) (*Client, error) {
	s := state.New()
	s.APIURL = cmd.String("api")
	s.KeyType = cmd.String("key-type")
	s.TTL = cmd.Duration("ttl")
	s.Insecure = cmd.Bool("insecure")
	if cmd.IsSet("token") {
		s.Token = cmd.String("token")
	}

	c := &Client{State: s}

	// Headless (service-account) mode has no signing identity: the API key
	// is a plain bearer token with no DPoP binding. Interactive mode creates
	// the machine key that binds the device session.
	if !s.IsServiceAccount() {
		signer, signerErr := tpm.New(util.ConfigPath(), cmd.Bool("require-tpm"))
		if signerErr != nil {
			return nil, signerErr
		}
		c.signer = signer
		c.proofer, signerErr = dpop.NewProofer(signer, dpop.ProoferOptions{})
		if signerErr != nil {
			return nil, signerErr
		}
	}

	if err := ssh.SetupKey(s.KeyType); err != nil {
		return nil, err
	}
	if err := c.SetupClients(); err != nil {
		return nil, err
	}

	if Healthy(ctx, s) {
		if err := c.verifyOnline(ctx); err != nil {
			if !s.HasCachedData() {
				return nil, err
			}
			// A refresh may have partially mutated the in-memory state, but
			// nothing is persisted until it succeeds. Reload the last-good
			// snapshot from disk so the fallback serves a consistent view.
			if loadErr := s.Cache.Load(); loadErr != nil {
				slog.Warn("failed to reload cache", "err", loadErr)
			}
			slog.Warn("online refresh failed, continuing with cached data", "err", err)
		}
	} else if !s.HasCachedData() {
		return nil, fmt.Errorf("backend unreachable and no cached data available")
	}

	return c, nil
}

// Healthy returns true if the backend is reachable.
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

// verifyOnline does a full online refresh: login, sync, pre-sign, config.
func (c *Client) verifyOnline(ctx context.Context) error {
	if err := c.login(ctx); err != nil {
		return err
	}
	if err := c.syncAll(ctx); err != nil {
		return err
	}
	// Commit the fresh snapshot before deriving artifacts from it. Only a
	// fully successful sync reaches this point, so the on-disk cache is
	// never left half-updated.
	if err := c.State.Save(); err != nil {
		return err
	}

	c.preSignCerts(ctx)

	if err := ssh.GenerateSSHConfig(c.State); err != nil {
		return err
	}
	if err := ssh.GenerateKnownHosts(c.State); err != nil {
		return err
	}
	return nil
}

// preSignCerts signs certificates for all known CAs before SSH needs them.
func (c *Client) preSignCerts(ctx context.Context) {
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(5)
	for _, ca := range c.State.CAs {
		g.Go(func() error {
			if err := c.Sign(ctx, ca); err != nil {
				slog.Warn("pre-sign cert failed", "ca", ca.Name, "err", err)
			}
			return nil
		})
	}
	_ = g.Wait()
}

// SignByTarget resolves a target by name and signs its certificate.
func (c *Client) SignByTarget(ctx context.Context, targetName string) error {
	targets := c.State.GetTargetsByName(targetName)
	if len(targets) == 0 {
		return fmt.Errorf("target %q not found", targetName)
	}
	if len(targets) > 1 {
		slog.Warn("target name is ambiguous, using first match",
			"target", targetName, "matches", len(targets))
	}
	ca := c.State.GetCAByID(targets[0].CAID)
	if ca == nil {
		return fmt.Errorf("CA %q not found", targets[0].CAID)
	}

	return c.Sign(ctx, *ca)
}

// Sign fetches a fresh certificate for ca and writes it to disk.
func (c *Client) Sign(ctx context.Context, ca state.CA) error {
	if err := ssh.VerifyCertificateByID(ca.ID, ca.PublicKey); err == nil {
		return nil // already signed, valid and under the current CA
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

	return util.WriteFile(util.Certificate(res.GetCaId()), signedCert, 0o600)
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
