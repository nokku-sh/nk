package api

import (
	"context"
	"errors"
	"fmt"

	"github.com/pkg/browser"

	nokkuv1 "github.com/nokku-sh/nk/internal/gen/nokku/v1"
	"github.com/nokku-sh/nk/internal/state"
)

// login prompts the user to log in via browser and syncs state.
func (c *Client) login(ctx context.Context) error {
	if c.State.IsServiceAccount() {
		return nil // Skip login
	}
	if c.State.User != nil {
		if err := c.syncUser(ctx); err == nil {
			return nil // Skip login
		}
	}

	pub, err := c.signer.Public()
	if err != nil {
		return fmt.Errorf("failed to read signing key: %w", err)
	}
	method := c.signer.Method()
	pubkey := string(pub)

	stream, err := c.ac.StreamCLILogin(ctx, &nokkuv1.StreamCLILoginRequest{
		AuthMethod: &method,
		AuthPubkey: &pubkey,
	})
	if err != nil {
		return err
	}
	defer func() { _ = stream.Close() }()

	if !stream.Receive() {
		return stream.Err()
	}

	verifyURL := stream.Msg().GetVerificationUrl()
	if verifyURL == "" {
		return errors.New("login failed, server did not provide verification URL")
	}

	if err = browser.OpenURL(verifyURL); err != nil {
		fmt.Printf("\nOpen this URL to authenticate:\n%s\n", verifyURL)
	}

	if !stream.Receive() {
		if err = stream.Err(); err != nil {
			return fmt.Errorf("login timed out: %w", err)
		}
		return errors.New("login failed, no response from server")
	}

	result := stream.Msg()
	c.State.User = state.MapUser(result.GetUser())
	if err = c.State.Save(); err != nil {
		return err
	}

	fmt.Printf("Authenticated as %s\n", result.GetUser().GetName())
	return nil
}
