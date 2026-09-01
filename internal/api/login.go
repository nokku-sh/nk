package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/browser"
)

// login obtains a session. Service accounts authenticate with their injected
// API key (no session). Interactive users run the RFC 8628 device flow: the
// CLI gets a user code, opens the browser, and polls for a DPoP-bound session
// token.
func (c *Client) login(ctx context.Context) error {
	if c.State.IsServiceAccount() {
		return nil // Skip login; the API key is injected via --token.
	}
	if c.State.SessionToken != "" {
		if c.State.SessionExpiresAt.IsZero() || time.Now().Before(c.State.SessionExpiresAt) {
			if err := c.syncUser(ctx); err == nil {
				return nil // Skip login; the session is still valid.
			}
		}
	}

	return c.deviceLogin(ctx)
}

// deviceLogin runs the RFC 8628 device flow and persists the returned
// DPoP-bound session token.
func (c *Client) deviceLogin(ctx context.Context) error {
	// The device must prove its key at token issuance, and the proof needs
	// the server nonce. Fetch it up front so the flow is a single poll; a
	// failure is not fatal, the token endpoint advertises a fresh nonce on
	// a use_dpop_nonce error and the loop retries (RFC 9449 section 8).
	nonce, _ := FetchNonce(ctx, c.httpc, c.State.APIURL)

	// Request a device code.
	deviceCode, userCode, verificationURI, err := c.beginDeviceAuth(ctx, nonce)
	if err != nil {
		return err
	}

	// Open the browser (the code is embedded in the complete URI).
	if err = browser.OpenURL(verificationURI); err != nil {
		fmt.Printf("\nOpen this URL to authenticate:\n%s\n", verificationURI)
	} else {
		fmt.Printf("\nWaiting for approval... (code: %s)\n", userCode)
	}

	// Poll for the session token.
	token, expiresIn, err := c.pollDeviceToken(ctx, deviceCode, nonce)
	if err != nil {
		return err
	}

	c.State.SessionToken = token
	if expiresIn > 0 {
		c.State.SessionExpiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
	}
	if err = c.State.Save(); err != nil {
		return err
	}

	// Resolve the authenticated user for the greeting and subject id.
	return c.syncUser(ctx)
}

// beginDeviceAuth asks the authorization server for a device code.
func (c *Client) beginDeviceAuth(
	ctx context.Context,
	nonce string,
) (deviceCode, userCode, verificationURI string, err error) {
	form := url.Values{}
	resp, _, err := c.postForm(ctx, "/auth/device", form, nonce)
	if err != nil {
		return "", "", "", err
	}
	var out struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
	}
	if err = json.Unmarshal(resp, &out); err != nil {
		return "", "", "", fmt.Errorf("device authorization: %w", err)
	}
	if out.DeviceCode == "" || out.UserCode == "" {
		return "", "", "", errors.New("device authorization: missing codes in response")
	}
	if out.VerificationURIComplete != "" {
		out.VerificationURI = out.VerificationURIComplete
	}
	if out.VerificationURI == "" {
		return "", "", "", errors.New("device authorization: missing verification URI")
	}
	return out.DeviceCode, out.UserCode, out.VerificationURI, nil
}

// pollDeviceToken polls the token endpoint until the user approves.
func (c *Client) pollDeviceToken(
	ctx context.Context,
	deviceCode, nonce string,
) (token string, expiresIn int, err error) {
	// Poll interval defaults to 5s; cap the total wait at the grant TTL.
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	timeout := time.NewTimer(15 * time.Minute)
	defer timeout.Stop()

	for {
		form := url.Values{"device_code": {deviceCode}}
		body, freshNonce, doErr := c.postForm(ctx, "/auth/device/token", form, nonce)
		// The nonce rotates every few minutes; when the server advertises a
		// fresh one, use it for the next poll.
		if freshNonce != "" {
			nonce = freshNonce
		}

		var out struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int    `json:"expires_in"`
		}
		tokenErr := json.Unmarshal(body, &out)

		var authErr struct {
			Error string `json:"error"`
		}
		decodeErr := json.Unmarshal(body, &authErr)

		switch {
		case doErr == nil && tokenErr == nil && out.AccessToken != "":
			return out.AccessToken, out.ExpiresIn, nil
		case decodeErr == nil && authErr.Error != "":
			switch authErr.Error {
			case "authorization_pending", "invalid_dpop_proof", "slow_down", "use_dpop_nonce":
				// keep polling (invalid_dpop_proof and use_dpop_nonce
				// carry a fresh nonce, consumed above, so the next poll
				// succeeds)
			case "access_denied", "expired_token":
				return "", 0, errors.New("device authorization: " + authErr.Error)
			default:
				return "", 0, errors.New("device authorization failed: " + authErr.Error)
			}
		case doErr != nil:
			// Transport error, or an HTTP error whose body carries no
			// RFC 8628 error code: retrying won't fix it.
			return "", 0, doErr
		default:
			// 2xx whose body is neither a token nor an RFC 8628 error:
			// don't spin until the timeout.
			return "", 0, fmt.Errorf(
				"device authorization: unexpected response: %s",
				strings.TrimSpace(string(body)),
			)
		}

		select {
		case <-ctx.Done():
			return "", 0, ctx.Err()
		case <-ticker.C:
		case <-timeout.C:
			return "", 0, errors.New("device authorization timed out")
		}
	}
}

// postForm sends an application/x-www-form-urlencoded POST to path, signing a
// DPoP proof over the request URL (no access token yet, so no ath claim). It
// returns the response body and, when the server advertised one, a fresh DPoP
// nonce the caller should use next.
func (c *Client) postForm(
	ctx context.Context,
	path string,
	form url.Values,
	nonce string,
) (body []byte, freshNonce string, err error) {
	encoded := form.Encode()
	u := strings.TrimRight(c.State.APIURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(encoded))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if c.proofer != nil {
		proof, serr := c.proofer.Sign(http.MethodPost, u, "", nonce)
		if serr != nil {
			return nil, "", serr
		}
		req.Header.Set("DPoP", proof)
	}

	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	if n := resp.Header.Get("DPoP-Nonce"); n != "" && n != nonce {
		freshNonce = n
	}
	if resp.StatusCode >= 400 {
		return data, freshNonce, fmt.Errorf(
			"device authorization: HTTP %d: %s",
			resp.StatusCode,
			strings.TrimSpace(string(data)),
		)
	}
	return data, freshNonce, nil
}
