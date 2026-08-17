package api

import (
	"context"
	"time"

	nokkuv1 "github.com/nokku-sh/nk/internal/gen/nokku/v1"
	"github.com/nokku-sh/nk/internal/ssh"
	"github.com/nokku-sh/nk/internal/state"
)

func (c *Client) syncAll(ctx context.Context) error {
	if !c.State.IsLoggedIn() {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	if err := c.syncUser(ctx); err != nil {
		return err
	}
	if err := c.syncWorkspaces(ctx); err != nil {
		return err
	}
	if err := c.syncAccess(ctx); err != nil {
		return err
	}
	return nil
}

// syncUser resolves the authenticated principal via Whoami. For interactive
// sessions the principal is a user; for service accounts it is the
// service-account identity (including its pinned workspace).
func (c *Client) syncUser(ctx context.Context) error {
	res, err := c.uc.Whoami(ctx, &nokkuv1.WhoamiRequest{})
	if err != nil {
		return err
	}

	switch {
	case res.GetUser() != nil:
		c.State.User = state.MapUser(res.GetUser())
		c.State.ServiceAccount = nil
	case res.GetServiceAccount() != nil:
		c.State.ServiceAccount = state.MapServiceAccount(res.GetServiceAccount())
		c.State.User = nil
	}
	return nil
}

func (c *Client) syncWorkspaces(ctx context.Context) error {
	res, err := c.wc.ListWorkspaces(ctx, &nokkuv1.ListWorkspacesRequest{})
	if err != nil {
		return err
	}

	c.State.Workspaces = state.MapWorkspaces(res.GetWorkspaces())
	return nil
}

// syncAccess fetches targets and CAs from all workspaces.
func (c *Client) syncAccess(ctx context.Context) error {
	if len(c.State.Workspaces) == 0 {
		c.State.Targets = []state.Target{}
		c.State.CAs = []state.CA{}
		return nil
	}

	subjectID := c.State.SubjectID()
	allTargets := make([]state.Target, 0)
	allCAs := make([]state.CA, 0)

	for _, ws := range c.State.Workspaces {
		res, err := c.tc.GetSubjectAccess(ctx, &nokkuv1.GetSubjectAccessRequest{
			WorkspaceId: &ws.ID,
			SubjectId:   &subjectID,
		})
		if err != nil {
			return err
		}

		allTargets = append(allTargets, state.MapTargets(res.GetTargets())...)
		allCAs = append(allCAs, state.MapCAs(res.GetCertificateAuthorities())...)
	}

	c.State.Targets = allTargets
	c.State.CAs = allCAs
	return ssh.CleanupCerts(c.State.CAs)
}
