package client

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

// ensureSession guarantees a usable session before a request. Service
// accounts authenticate with their injected API key (no session).
// Interactive callers may run the RFC 8628 device flow; non-interactive
// callers fail fast with ErrNotLoggedIn instead of blocking on a browser.
//
// The persisted expiry time is trusted locally: no probe request is spent on
// validation, and a server-side rejection surfaces as CodeUnauthenticated,
// which Sync turns into a single re-login and retry.
func (c *Client) ensureSession(ctx context.Context, interactive bool) error {
	if c.State.IsServiceAccount() {
		return nil // Skip login; the API key is injected via --token.
	}
	if c.State.SessionValid() {
		return nil // Skip login; the session is still valid.
	}
	if !interactive {
		return errors.New("not logged in (run nk login)")
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
	if c.dpopAuth != nil {
		nonce, apiURL, _ := FetchNonce(ctx, c.httpc, c.State.APIURL)
		c.dpopAuth.set(nonce, apiURL)
	}

	// Request a device code.
	deviceCode, userCode, verificationURI, err := c.beginDeviceAuth(ctx)
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
	token, expiresIn, err := c.pollDeviceToken(ctx, deviceCode)
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

	// The identity itself is resolved by the following access sync; the
	// device flow only needs to establish the session.
	return nil
}

// beginDeviceAuth asks the authorization server for a device code.
func (c *Client) beginDeviceAuth(
	ctx context.Context,
) (deviceCode, userCode, verificationURI string, err error) {
	form := url.Values{}
	resp, err := c.postForm(ctx, "/auth/device", form)
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
	deviceCode string,
) (token string, expiresIn int, err error) {
	// Poll interval defaults to 5s; cap the total wait at the grant TTL.
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	timeout := time.NewTimer(15 * time.Minute)
	defer timeout.Stop()

	for {
		form := url.Values{"device_code": {deviceCode}}
		body, doErr := c.postForm(ctx, "/auth/device/token", form)

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
// DPoP proof over the request URL (no access token yet, so no ath claim). The
// proof binds to the canonical API URL the server advertises, which may
// differ from the configured one the request goes to. Any nonce and canonical
// URL the response advertises are learned, so the next proof succeeds.
func (c *Client) postForm(
	ctx context.Context,
	path string,
	form url.Values,
) (body []byte, err error) {
	encoded := form.Encode()
	u := strings.TrimRight(c.State.APIURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if c.proofer != nil && c.dpopAuth != nil {
		htu := c.dpopAuth.htuBase() + path
		proof, serr := c.proofer.Sign(http.MethodPost, htu, "", c.dpopAuth.currentNonce())
		if serr != nil {
			return nil, serr
		}
		req.Header.Set("DPoP", proof)
	}

	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if c.dpopAuth != nil {
		c.dpopAuth.learnResponse(resp.Header)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return data, fmt.Errorf(
			"device authorization: HTTP %d: %s",
			resp.StatusCode,
			strings.TrimSpace(string(data)),
		)
	}
	return data, nil
}
