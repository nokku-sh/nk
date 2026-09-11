package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nk/internal/gen/nokku/v1"
	"github.com/nokku-sh/nk/internal/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nk/internal/state"
)

// captureTargetService records the create request and answers with the target
// the backend would have made.
type captureTargetService struct {
	nokkuv1connect.UnimplementedTargetServiceHandler

	got *nokkuv1.CreateTargetRequest
}

func (s *captureTargetService) CreateTarget(
	_ context.Context,
	req *nokkuv1.CreateTargetRequest,
) (*nokkuv1.CreateTargetResponse, error) {
	s.got = req
	return &nokkuv1.CreateTargetResponse{Target: &nokkuv1.Target{
		Id:   new("target-1"),
		Name: new("fair-juniper"),
	}}, nil
}

func TestCreateTarget(t *testing.T) {
	t.Parallel()

	svc := &captureTargetService{}
	mux := http.NewServeMux()
	mux.Handle(nokkuv1connect.NewTargetServiceHandler(svc))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	c := &Client{State: &state.State{APIURL: server.URL, SessionToken: "sess-token"}}
	c.tc = nokkuv1connect.NewTargetServiceClient(http.DefaultClient, server.URL)

	created, err := c.CreateTarget(
		context.Background(), "ws-1", "ca-1", "", "ssh-ed25519 AAAA", []string{"10.0.0.5"},
	)
	require.NoError(t, err)

	assert.Equal(t, "fair-juniper", created.GetName(), "the server-generated name comes back")
	require.NotNil(t, svc.got)
	assert.Empty(t, svc.got.GetName(), "an empty name asks the server to generate one")
	assert.Equal(t, "ws-1", svc.got.GetWorkspaceId())
	assert.Equal(t, "ca-1", svc.got.GetCaId())
	assert.Equal(t, []string{"10.0.0.5"}, svc.got.GetEndpoints())
	assert.Equal(t, "ssh-ed25519 AAAA", svc.got.GetHostPublicKey())
}
