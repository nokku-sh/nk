package api

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	"connectrpc.com/connect"

	"github.com/nokku-sh/nk/internal/gen/nokku/v1/nokkuv1connect"
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

func (c *Client) SetupClients() error {
	httpc, err := newHTTPClient(c.State.Insecure)
	if err != nil {
		return err
	}

	opts := connect.WithInterceptors(withRetry(), WithAuth(c.State, c.signer))
	c.ac = nokkuv1connect.NewAuthServiceClient(httpc, c.State.APIURL, opts)
	c.uc = nokkuv1connect.NewUserServiceClient(httpc, c.State.APIURL, opts)
	c.sa = nokkuv1connect.NewServiceAccountServiceClient(httpc, c.State.APIURL, opts)
	c.wc = nokkuv1connect.NewWorkspaceServiceClient(httpc, c.State.APIURL, opts)
	c.cc = nokkuv1connect.NewCertificateServiceClient(httpc, c.State.APIURL, opts)
	c.tc = nokkuv1connect.NewTargetServiceClient(httpc, c.State.APIURL, opts)
	return nil
}
