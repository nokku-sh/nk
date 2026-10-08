// Package client manages the connection to the Nokku backend.
package client

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/mizuchilabs/kata/buildinfo"
	"github.com/mizuchilabs/kata/fsutil"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/nokku-sh/mon/dpopclient"
	"github.com/nokku-sh/mon/tpm"
	"github.com/nokku-sh/nk/internal/enclave"
	"github.com/nokku-sh/nk/internal/paths"
	"github.com/nokku-sh/nk/internal/ssh"
	"github.com/nokku-sh/nk/internal/state"
	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"
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

	auth    nokkuv1connect.AuthServiceClient
	certs   nokkuv1connect.CertificateServiceClient
	targets nokkuv1connect.TargetServiceClient
	daemons nokkuv1connect.DaemonServiceClient
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
		auth = &bearerAuth{token: s.Token, ua: buildinfo.UserAgent("nk")}
	} else {
		proofer, perr := dpopclient.NewProofer(tpm.SignerOptions{
			Salt:       []byte(signerSalt),
			StatePath:  paths.SignerStateFile(),
			RequireTPM: s.RequireTPM,
			Recreate:   true,
			Enclave:    enclave.New(),
		})
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
	c.auth = nokkuv1connect.NewAuthServiceClient(httpc, s.APIURL, opts)
	c.certs = nokkuv1connect.NewCertificateServiceClient(httpc, s.APIURL, opts)
	c.targets = nokkuv1connect.NewTargetServiceClient(httpc, s.APIURL, opts)
	c.daemons = nokkuv1connect.NewDaemonServiceClient(httpc, s.APIURL, opts)
	return c, nil
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
// working while the backend is down or the session has run out.
func (c *Client) SyncOrCache(ctx context.Context, interactive bool) error {
	err := c.Sync(ctx, interactive)
	if err == nil {
		return nil
	}
	if loadErr := c.State.LoadCache(); loadErr != nil || !c.State.HasCachedData() {
		return fmt.Errorf("sync with Nokku failed and nothing is cached yet: %w", err)
	}
	slog.Warn("sync with Nokku failed, using cached access", "err", err)
	c.State.MarkSyncFailed()
	return nil
}

func (c *Client) sync(ctx context.Context, interactive bool) error {
	if err := c.ensureSession(ctx, interactive); err != nil {
		return err
	}
	syncCtx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()
	res, err := c.targets.GetMyAccess(syncCtx, &nokkuv1.GetMyAccessRequest{})
	if err != nil {
		return err
	}

	cache := state.FromAccess(res)
	cache.Server = c.State.APIURL
	cache.SyncedAt = time.Now()
	if err = ssh.CleanupCerts(cache.Targets); err != nil {
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
	if _, err := c.auth.Logout(ctx, &nokkuv1.LogoutRequest{}); err != nil {
		slog.Debug("revoke session on the backend", "err", err)
	}
}

// EnsureCert makes sure a fresh certificate for target is on disk, see
// ssh.CertFresh. The backend signs it for this one server, with the accounts
// granted there. When signing fails the one on disk stays, so ssh keeps
// working offline for as long as it is valid.
func (c *Client) EnsureCert(ctx context.Context, target state.Target, ca state.CA) error {
	if ssh.CertFresh(target, ca) {
		return nil
	}
	if err := c.ensureSession(ctx, false); err != nil {
		return err
	}
	pubKey, err := ssh.PubKey()
	if err != nil {
		return err
	}

	req := &nokkuv1.SignSSHCertificateRequest{
		TargetId:  new(target.ID),
		PublicKey: new(pubKey),
	}
	if c.State.TTL > 0 {
		req.Ttl = durationpb.New(c.State.TTL)
	}
	signCtx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()
	res, err := c.certs.SignSSHCertificate(signCtx, req)
	if err != nil {
		return err
	}

	signed := []byte(res.GetSignedCertificate())
	if err = ssh.CheckCert(signed, ca.PublicKey, 0); err != nil {
		return fmt.Errorf("backend returned an unusable certificate: %w", err)
	}
	return fsutil.WriteFile(paths.SSHCertificate(target.ID), signed, 0o600)
}

// TargetPrincipals returns the certificate principals allowed per account on
// a manual target. The backend builds them, sshd compares them as they are.
func (c *Client) TargetPrincipals(ctx context.Context, t *state.Target) (map[string][]string, error) {
	res, err := c.targets.GetTargetPrincipals(ctx, &nokkuv1.GetTargetPrincipalsRequest{
		TargetId: new(t.ID),
	})
	if err != nil {
		return nil, err
	}
	grants := make(map[string][]string, len(res.GetPrincipals()))
	for _, p := range res.GetPrincipals() {
		grants[p.GetUsername()] = p.GetCertPrincipals()
	}
	return grants, nil
}

// ReportTarget reports a manual target's accounts, host key, and endpoints,
// which also stamps its last sync.
func (c *Client) ReportTarget(ctx context.Context, t *state.Target, accounts []string, hostKey string) error {
	_, err := c.targets.SyncTargetUsers(ctx, &nokkuv1.SyncTargetUsersRequest{
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
	res, err := c.targets.CreateTarget(ctx, &nokkuv1.CreateTargetRequest{
		CaId:          new(t.CAID),
		Name:          new(t.Name),
		HostPublicKey: new(t.HostPublicKey),
		Endpoints:     t.Endpoints,
	})
	if err != nil {
		return nil, err
	}
	created := state.MapTarget(res.GetTarget())
	created.CAID = t.CAID
	return &created, nil
}

func (c *Client) DeleteTarget(ctx context.Context, t *state.Target) error {
	_, err := c.targets.DeleteTarget(ctx, &nokkuv1.DeleteTargetRequest{
		Id: new(t.ID),
	})
	return err
}

// ListX509CAs returns the active X.509 CAs. They are not linked to targets,
// so they are fetched separately from the access sync.
func (c *Client) ListX509CAs(ctx context.Context) ([]*nokkuv1.CertificateAuthority, error) {
	res, err := c.certs.ListCertificateAuthorities(ctx, &nokkuv1.ListCertificateAuthoritiesRequest{})
	if err != nil {
		return nil, err
	}
	var out []*nokkuv1.CertificateAuthority
	for _, ca := range res.GetCertificateAuthorities() {
		if ca.GetAuthorityType() == nokkuv1.AuthorityType_AUTHORITY_TYPE_X509 && ca.GetIsActive() {
			out = append(out, ca)
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
		CaId:  new(ca.GetId()),
		Csr:   new(csrPEM),
		Usage: usage.Enum(),
	}
	if c.State.TTL > 0 {
		req.Ttl = durationpb.New(c.State.TTL)
	}
	return c.certs.SignX509Certificate(ctx, req)
}
