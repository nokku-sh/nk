package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nokku-sh/nk/internal/state"
)

// fakeDeviceFlow mirrors nokku's iam.DeviceFlow semantics closely enough to
// exercise the client's poll loop: pending polls skip DPoP checks, the
// approved poll verifies the proof (nonce, htu, replay), use_dpop_nonce
// advertises only a DPoP-Nonce header, and the replay store persists across
// logins. The canonical URL (what proofs must bind to) differs from the
// server's listen URL, like a dev deployment where NOKKU_BASE_URL points at
// the Vite dev port while the CLI talks to the raw API port.
type fakeDeviceFlow struct {
	mu         sync.Mutex
	grants     map[string]*fakeGrant // by device code
	replay     map[string]bool
	nonce      string
	baseURL    string // canonical URL proofs must bind to
	listenURL  string // where the endpoints are actually reached
	violations map[string]int
	lastPoll   map[string]time.Time
}

type fakeGrant struct {
	deviceCode string
	userCode   string
	status     string
}

func newFakeDeviceFlow(t *testing.T) (*fakeDeviceFlow, *httptest.Server) {
	t.Helper()
	f := &fakeDeviceFlow{
		grants:     map[string]*fakeGrant{},
		replay:     map[string]bool{},
		nonce:      "test-nonce",
		lastPoll:   map[string]time.Time{},
		violations: map[string]int{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/device", f.begin)
	mux.HandleFunc("POST /auth/device/token", f.poll)
	mux.HandleFunc("GET /auth/device/nonce", f.nonceEndpoint)
	srv := httptest.NewServer(mux)
	f.listenURL = srv.URL
	f.baseURL = "http://localhost:5173"
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeDeviceFlow) begin(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	g := &fakeGrant{
		deviceCode: fmt.Sprintf("dev-%d", len(f.grants)),
		userCode:   fmt.Sprintf("USER-%d", len(f.grants)),
		status:     "pending",
	}
	f.grants[g.deviceCode] = g
	writeJSON(w, map[string]any{
		"device_code":               g.deviceCode,
		"user_code":                 g.userCode,
		"verification_uri":          f.baseURL + "/device",
		"verification_uri_complete": f.baseURL + "/device?user_code=" + g.userCode,
		"interval":                  1,
	})
}

func (f *fakeDeviceFlow) poll(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	code := r.FormValue("device_code")
	g, ok := f.grants[code]
	if !ok {
		writeOAuthErr(w, "expired_token")
		return
	}
	switch g.status {
	case "pending":
		// pollTrack: the required interval grows by 5s per too-fast poll.
		required := time.Second + time.Duration(f.violations[code])*5*time.Second
		now := time.Now()
		if last := f.lastPoll[code]; !last.IsZero() && now.Sub(last) < required {
			f.violations[code]++
			writeOAuthErr(w, "slow_down")
			return
		}
		f.lastPoll[code] = now
		writeOAuthErr(w, "authorization_pending")
	case "denied":
		delete(f.grants, code)
		writeOAuthErr(w, "access_denied")
	case "approved":
		jkt, derr := f.verifyProof(r)
		if derr != "" {
			// Mirror the server's advertisement: the canonical URL rides
			// every proof failure, the nonce on all of them too.
			w.Header().Set(urlHeader, f.baseURL)
			w.Header().Set("DPoP-Nonce", f.nonce)
			writeOAuthErr(w, derr)
			return
		}
		delete(f.grants, code)
		writeJSON(w, map[string]any{
			"access_token": "tok-for-" + jkt,
			"token_type":   "DPoP",
		})
	}
}

func (f *fakeDeviceFlow) nonceEndpoint(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set(urlHeader, f.baseURL)
	w.Header().Set("DPoP-Nonce", f.nonce)
	w.WriteHeader(http.StatusNoContent)
}

// verifyProof checks the DPoP claims the server checks at issuance. The
// signature itself is not verified; the loop behavior under test does not
// depend on it.
func (f *fakeDeviceFlow) verifyProof(r *http.Request) (string, string) {
	proof := r.Header.Get("DPoP")
	if proof == "" {
		return "", "" // unbound session, still succeeds
	}
	payload, err := base64.RawURLEncoding.DecodeString(
		strings.Split(proof, ".")[1],
	)
	if err != nil {
		return "", "invalid_dpop_proof"
	}
	var claims struct {
		HTM   string `json:"htm"`
		HTU   string `json:"htu"`
		IAT   int64  `json:"iat"`
		JTI   string `json:"jti"`
		Nonce string `json:"nonce"`
	}
	if err = json.Unmarshal(payload, &claims); err != nil {
		return "", "invalid_dpop_proof"
	}
	if claims.HTM != http.MethodPost ||
		!strings.EqualFold(claims.HTU, f.baseURL+"/auth/device/token") {
		return "", "invalid_dpop_proof"
	}
	if claims.IAT == 0 || time.Since(time.Unix(claims.IAT, 0)) > time.Minute {
		return "", "invalid_dpop_proof"
	}
	if claims.Nonce != f.nonce {
		return "", "use_dpop_nonce"
	}
	if f.replay[claims.JTI] {
		return "", "invalid_dpop_proof"
	}
	f.replay[claims.JTI] = true
	return "jkt", ""
}

func (f *fakeDeviceFlow) approve(deviceCode string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.grants[deviceCode].status = "approved"
}

func writeOAuthErr(w http.ResponseWriter, code string) {
	writeJSON(w, map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// runDeviceLogin drives the same path deviceLogin uses, with the approval
// injected shortly after the flow starts, like a user clicking accept.
func runDeviceLogin(t *testing.T, c *Client, f *fakeDeviceFlow) (string, error) {
	t.Helper()
	d, err := c.beginDeviceAuth(context.Background())
	if err != nil {
		return "", err
	}

	go func() {
		time.Sleep(1500 * time.Millisecond)
		f.approve(d.deviceCode)
	}()

	token, _, err := c.pollDeviceToken(context.Background(), d.deviceCode, d.interval)
	return token, err
}

func TestDeviceFlowTwoConsecutiveLogins(t *testing.T) {
	f, srv := newFakeDeviceFlow(t)

	c := &Client{State: &state.State{APIURL: srv.URL}, httpc: srv.Client()}
	c.dpop = &dpopAuth{state: c.State, proofer: newTestProofer(t), httpc: srv.Client()}

	for i := range 2 {
		token, err := runDeviceLogin(t, c, f)
		if err != nil {
			t.Fatalf("login %d: %v", i+1, err)
		}
		if token == "" {
			t.Fatalf("login %d: empty token", i+1)
		}
	}
}
