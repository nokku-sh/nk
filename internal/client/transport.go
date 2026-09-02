package client

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/nokku-sh/nk/internal/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nk/internal/state"
)

func newHTTPClient(insecure bool) (*http.Client, error) {
	proto := new(http.Protocols)
	proto.SetHTTP1(false)
	proto.SetHTTP2(true)
	proto.SetUnencryptedHTTP2(true)

	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("expected *http.Transport as default transport")
	}
	t := base.Clone()
	t.Protocols = proto
	if t.TLSClientConfig == nil {
		t.TLSClientConfig = &tls.Config{}
	}
	t.TLSClientConfig.MinVersion = tls.VersionTLS13
	if insecure {
		t.TLSClientConfig.InsecureSkipVerify = true // #nosec G402
	}

	t.DialContext = (&net.Dialer{
		Timeout:   3 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext
	return &http.Client{Transport: t}, nil
}

// Reachable reports whether the backend answers a plain HTTP request within
// a short timeout. It is only a diagnostic signal; commands never probe
// reachability before acting, they attempt the real request and fail fast.
func Reachable(ctx context.Context, st *state.State) bool {
	httpc, err := newHTTPClient(st.Insecure)
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

// setupClients constructs the connectrpc clients. Authentication is layered:
// the DPoP interceptor signs interactive device sessions, the identity
// interceptor adds the service-account API key and client headers.
func (c *Client) setupClients() error {
	httpc, err := newHTTPClient(c.State.Insecure)
	if err != nil {
		return err
	}
	c.httpc = httpc

	c.dpop, err = withDPoP(c.State, httpc)
	if err != nil {
		return err
	}
	interceptors := []connect.Interceptor{withRetry(), withUA(), c.dpop}
	opts := connect.WithInterceptors(interceptors...)

	c.cc = nokkuv1connect.NewCertificateServiceClient(httpc, c.State.APIURL, opts)
	c.tc = nokkuv1connect.NewTargetServiceClient(httpc, c.State.APIURL, opts)
	return nil
}
