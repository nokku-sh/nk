package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
// session token.
func (c *Client) deviceLogin(ctx context.Context) error {
	slog.Debug("starting device flow", "api", c.State.APIURL)

	// Bootstrap the DPoP nonce and canonical URL up front, so the first
	// approved poll already carries a valid proof.
	// Best effort: a failure just costs one rejected poll, which self-heals.
	if a := c.dpop; a != nil && a.proofer != nil {
		if nonce, serverURL, err := FetchNonce(ctx, c.httpc, c.State.APIURL); err == nil {
			a.learn(nonce, serverURL)
		}
	}

	d, err := c.beginDeviceAuth(ctx)
	if err != nil {
		return err
	}

	// Open the browser (the code is embedded in the complete URI).
	if err = browser.OpenURL(d.verificationURI); err != nil {
		fmt.Printf("\nOpen this URL to authenticate:\n%s\n", d.verificationURI)
	} else {
		fmt.Printf("\nWaiting for approval... (code: %s)\n", d.userCode)
	}

	// Poll for the session token.
	token, expiresIn, err := c.pollDeviceToken(ctx, d.deviceCode, d.interval)
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

// deviceAuth is the beginDeviceAuth response.
type deviceAuth struct {
	deviceCode      string
	userCode        string
	verificationURI string
	interval        int
}

// beginDeviceAuth asks the authorization server for a device code.
func (c *Client) beginDeviceAuth(
	ctx context.Context,
) (deviceAuth, error) {
	form := url.Values{}
	resp, err := c.postForm(ctx, "/auth/device", form)
	if err != nil {
		return deviceAuth{}, err
	}
	var out struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		Interval                int    `json:"interval"`
	}
	if err = json.Unmarshal(resp, &out); err != nil {
		return deviceAuth{}, fmt.Errorf("device authorization: %w", err)
	}
	if out.DeviceCode == "" || out.UserCode == "" {
		return deviceAuth{}, errors.New("device authorization: missing codes in response")
	}
	if out.VerificationURIComplete != "" {
		out.VerificationURI = out.VerificationURIComplete
	}
	if out.VerificationURI == "" {
		return deviceAuth{}, errors.New("device authorization: missing verification URI")
	}
	return deviceAuth{
		deviceCode:      out.DeviceCode,
		userCode:        out.UserCode,
		verificationURI: out.VerificationURI,
		interval:        out.Interval,
	}, nil
}

// pollDeviceToken polls the token endpoint until the user approves. interval
// is the server's poll interval hint in seconds.
func (c *Client) pollDeviceToken(
	ctx context.Context,
	deviceCode string,
	interval int,
) (token string, expiresIn int, err error) {
	// Cap the total wait at the grant TTL.
	timeout := time.NewTimer(15 * time.Minute)
	defer timeout.Stop()

	wait := time.Duration(interval) * time.Second
	if wait <= 0 {
		wait = 5 * time.Second
	}
	ticker := time.NewTicker(wait)
	defer ticker.Stop()

	bootstrapped := false

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
			slog.Debug("device flow poll", "api", c.State.APIURL, "response", authErr.Error)
			switch authErr.Error {
			case "authorization_pending":
				// keep polling
			case "use_dpop_nonce":
				// the fresh nonce was learned in postForm; re-sign
				// and retry without waiting the poll interval
				continue
			case "invalid_dpop_proof":
				// A proof can be rejected before the nonce check when
				// the htu is wrong: the configured API URL differs from
				// the canonical URL the server binds proofs to.
				if !bootstrapped && c.dpop != nil {
					bootstrapped = true
					if nonce, serverURL, nerr := FetchNonce(ctx, c.httpc, c.State.APIURL); nerr == nil {
						c.dpop.learn(nonce, serverURL)
						continue
					}
				}
			case "slow_down":
				// RFC 8628 section 3.5: grow the interval by 5s. The
				// server counts violations per grant and its required
				// interval keeps growing, so this must be honored.
				wait += 5 * time.Second
				ticker.Reset(wait)
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
			// 2xx whose body is neither a token nor an RFC 8628 error
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

	if a := c.dpop; a != nil && a.proofer != nil {
		proof, perr := a.proofer.Sign(
			http.MethodPost,
			a.htuBase()+path,
			"",
			a.currentNonce(),
		)
		if perr != nil {
			return nil, perr
		}
		req.Header.Set("DPoP", proof)
	}

	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	// Learn before the status check: the use_dpop_nonce rejection is the
	// response that carries the nonce the retry needs.
	if a := c.dpop; a != nil {
		a.learnResponse(resp.Header)
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
