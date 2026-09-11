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

	"github.com/nokku-sh/mon/dpopclient"
)

type deviceAuth struct {
	deviceCode      string
	userCode        string
	verificationURI string
	interval        int
}

// ensureSession guarantees a usable session before a request. Service
// accounts use their injected API key, non-interactive callers fail fast
// instead of blocking on a browser. The persisted expiry is trusted locally,
// so a server-side rejection only surfaces later as CodeUnauthenticated,
// which Sync turns into one re-login.
func (c *Client) ensureSession(ctx context.Context, interactive bool) error {
	if c.State.IsServiceAccount() {
		return nil
	}
	if c.State.SessionValid() {
		return nil
	}
	if !interactive {
		return errors.New("not logged in (run nk login)")
	}
	return c.deviceLogin(ctx)
}

func (c *Client) deviceLogin(ctx context.Context) error {
	slog.Debug("starting device flow", "api", c.State.APIURL)

	// Bootstrap the nonce and canonical URL up front, so the first approved
	// poll already carries a valid proof. Best effort, a failure only costs
	// one rejected poll.
	if c.dpop != nil {
		if nonce, serverURL, err := dpopclient.FetchNonce(ctx, c.httpc, c.State.APIURL); err == nil {
			c.dpop.Learn(nonce, serverURL)
		}
	}

	d, err := c.beginDeviceAuth(ctx)
	if err != nil {
		return err
	}

	// The verification URI already carries the code.
	if err = browser.OpenURL(d.verificationURI); err != nil {
		fmt.Printf("\nOpen this URL to authenticate:\n%s\n", d.verificationURI)
	} else {
		fmt.Printf("\nWaiting for approval... (code: %s)\n", d.userCode)
	}

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

	// Identity comes from the access sync that runs after login.
	return nil
}

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
				// postForm learned the fresh nonce, retry without waiting
				// for the next tick
				continue
			case "invalid_dpop_proof":
				// The configured API URL can differ from the canonical URL
				// proofs bind to. The first rejection is not fatal, learn
				// the real one and retry.
				if !bootstrapped && c.dpop != nil {
					bootstrapped = true
					if nonce, serverURL, nerr := dpopclient.FetchNonce(ctx, c.httpc, c.State.APIURL); nerr == nil {
						c.dpop.Learn(nonce, serverURL)
						continue
					}
				}
			case "slow_down":
				// RFC 8628 section 3.5. The server counts violations per
				// grant and its required interval keeps growing, so this
				// must be honored.
				wait += 5 * time.Second
				ticker.Reset(wait)
			case "access_denied", "expired_token":
				return "", 0, errors.New("device authorization: " + authErr.Error)
			default:
				return "", 0, errors.New("device authorization failed: " + authErr.Error)
			}
		case doErr != nil:
			// A transport error or an HTTP error without an RFC 8628 code
			// won't fix itself on retry.
			return "", 0, doErr
		default:
			// Never echo the body, a malformed response can still carry a token.
			return "", 0, errors.New("device authorization: unexpected response")
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

// postForm POSTs an x-www-form-urlencoded body with a DPoP proof. The proof
// binds to the canonical API URL the server advertises, which can differ from
// the configured one the request goes to.
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

	if c.dpop != nil {
		proof, perr := c.dpop.Proof(http.MethodPost, c.dpop.HtuBase()+path)
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

	// Learn before the status check, the rejection carries the nonce the
	// retry needs.
	if c.dpop != nil {
		c.dpop.LearnHeaders(resp.Header)
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
