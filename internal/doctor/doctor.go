package doctor

// The `nk doctor` diagnostics command produces pass/fail checks as text
// or JSON for CI.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/mizuchilabs/kata/buildinfo"

	"github.com/nokku-sh/nk/internal/api"
	"github.com/nokku-sh/nk/internal/ssh"
	"github.com/nokku-sh/nk/internal/state"
	"github.com/nokku-sh/nk/internal/tpm"
	"github.com/nokku-sh/nk/internal/util"
)

// Status is the outcome of a single check.
type Status string

const (
	StatusOK   Status = "ok"
	StatusWarn Status = "warn"
	StatusFail Status = "fail"
	StatusInfo Status = "info"
)

const goosWindows = "windows"

// errNotLoggedIn signals that no signing identity exists on this machine.
var errNotLoggedIn = errors.New("no signing identity exists (run nk login)")

// Check is a single diagnostic result.
type Check struct {
	Section string `json:"section"`
	Name    string `json:"name"`
	Status  Status `json:"status"`
	Detail  string `json:"detail,omitempty"`
}

// Report is the full doctor output.
type Report struct {
	Fixes  []string `json:"fixes,omitempty"`
	Checks []Check  `json:"checks"`
}

// RunDoctor collects all checks without triggering a login or mutating state
// (except when fix is set, which explicitly asks for repairs).
func RunDoctor(ctx context.Context, s *state.State, fix bool) Report {
	var rep Report
	add := func(section, name string, status Status, detail string) {
		rep.Checks = append(rep.Checks, Check{
			Section: section,
			Name:    name,
			Status:  status,
			Detail:  detail,
		})
	}

	if fix {
		rep.Fixes = repair(s)
	}

	checkSystem(ctx, add)
	checkConfig(add, s)

	signerErr := openSigner(s)
	checkIdentity(add, s, signerErr)
	checkConnectivity(ctx, add, s)
	checkSSH(add)
	checkCerts(add, s)
	return rep
}

// ExitCode returns 0 when healthy, 1 when there are warnings, and 2 when
// any check failed.
func (r Report) ExitCode() int {
	code := 0
	for _, c := range r.Checks {
		switch c.Status {
		case StatusFail:
			return 2
		case StatusWarn:
			code = 1
		case StatusOK, StatusInfo:
		}
	}
	return code
}

func hostname() string {
	if h, err := os.Hostname(); err == nil {
		return h
	}
	return "unknown"
}

// openSigner loads the existing signing identity without creating one.
// Returns errNotLoggedIn when none exists yet. Headless (service-account)
// mode has no signing identity; it returns errNotLoggedIn too, which
// checkIdentity reports as "not logged in" for headless runs.
func openSigner(s *state.State) error {
	if s.Token != "" {
		return errNotLoggedIn
	}
	if tpm.SignerMethod(util.ConfigPath()) == "" {
		return errNotLoggedIn
	}
	_, err := tpm.New(util.ConfigPath(), s.RequireTPM)
	return err
}

func checkSystem(ctx context.Context, add func(string, string, Status, string)) {
	add("System", "version", StatusInfo, buildinfo.Version)
	add("System", "hostname", StatusInfo, hostname())
	add("System", "platform", StatusInfo, runtime.GOOS+"/"+runtime.GOARCH)
	add("System", "config", StatusInfo, util.ConfigPath())

	if util.IsTerminal(os.Stdout) {
		add("System", "environment", StatusInfo, "interactive")
	} else {
		add("System", "environment", StatusInfo, "headless (non-interactive)")
	}

	if path, version, ok := sshBinary(ctx); ok {
		add("System", "ssh", StatusOK, version+" at "+path)
	} else {
		add("System", "ssh", StatusFail, "ssh not found on PATH (required to connect)")
	}

	switch err := tpm.Available(); {
	case err == nil:
		add("System", "TPM 2.0", StatusOK, "available")
	case runtime.GOOS != "linux" && runtime.GOOS != goosWindows:
		add("System", "TPM 2.0", StatusInfo, "not supported on "+runtime.GOOS)
	default:
		detail := err.Error()
		if errors.Is(err, os.ErrPermission) {
			detail += " (hint: sudo usermod -aG tss $USER, then log in again)"
		}
		add("System", "TPM 2.0", StatusWarn, detail)
	}
}

func checkConfig(add func(string, string, Status, string), s *state.State) {
	if !util.FileExists(util.ConfigFile()) {
		add("Configuration", "config.json", StatusInfo, "no config yet (run nk login)")
	} else {
		var cfg state.Config
		if err := cfg.Load(); err != nil {
			add("Configuration", "config.json", StatusFail, err.Error())
		} else {
			add("Configuration", "config.json", StatusOK, effectiveConfig(s))
		}
	}

	dir := util.ConfigPath()
	if info, err := os.Stat(dir); err != nil {
		add("Configuration", "data directory", StatusFail, err.Error())
	} else if runtime.GOOS != goosWindows && info.Mode().Perm() != 0o700 {
		add("Configuration", "data directory", StatusWarn,
			fmt.Sprintf("%s has mode %04o (want 0700)", dir, info.Mode().Perm()))
	} else {
		add("Configuration", "data directory", StatusOK, dir)
	}

	checkFilePerms(add, "private key", util.KeyFile(), 0o600)
}

func effectiveConfig(s *state.State) string {
	ttl := "server default"
	if s.TTL > 0 {
		ttl = util.HumanizeDuration(s.TTL)
	}
	return fmt.Sprintf("ttl=%s, insecure=%v, require-tpm=%v", ttl, s.Insecure, s.RequireTPM)
}

func checkFilePerms(add func(string, string, Status, string), name, path string, want os.FileMode) {
	if runtime.GOOS == goosWindows || !util.FileExists(path) {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		add("Configuration", name, StatusWarn, err.Error())
		return
	}
	if info.Mode().Perm() != want {
		add("Configuration", name, StatusWarn,
			fmt.Sprintf("%s has mode %04o (want %04o)", path, info.Mode().Perm(), want))
	}
}

func checkIdentity(add func(string, string, Status, string), s *state.State, signerErr error) {
	switch {
	case s.ServiceAccount != nil:
		add("Identity", "signed in as", StatusOK, "service account "+s.ServiceAccount.Name)
	case s.User != nil:
		add("Identity", "signed in as", StatusOK,
			fmt.Sprintf("%s <%s>", s.User.Username, s.User.Email))
	default:
		add("Identity", "signed in as", StatusInfo, "not logged in")
	}

	add(
		"Identity",
		"workspaces",
		StatusInfo,
		fmt.Sprintf(
			"%d workspaces, %d targets, %d CAs",
			len(s.Workspaces),
			len(s.Targets),
			len(s.CAs),
		),
	)

	switch method := tpm.SignerMethod(util.ConfigPath()); {
	case method == "":
		add("Identity", "signing identity", StatusInfo, "not logged in (run nk login)")
	case signerErr != nil:
		add("Identity", "signing identity", StatusFail, signerErr.Error())
	case method == tpm.MethodTPM:
		add("Identity", "signing identity", StatusOK, "tpm (machine-bound)")
	default:
		add("Identity", "signing identity", StatusOK, "soft (encrypted at rest)")
	}

	if ssh.TPMKeyActive() || util.FileExists(util.KeyFile()) {
		add("Identity", "ssh identity", StatusOK, ssh.IdentityStatus())
	} else {
		add("Identity", "ssh identity", StatusInfo, ssh.IdentityStatus())
	}
}

func checkConnectivity(
	ctx context.Context,
	add func(string, string, Status, string),
	s *state.State,
) {
	if api.Healthy(ctx, s) {
		add("Connectivity", "API", StatusOK, "connected")
	} else {
		add("Connectivity", "API", StatusWarn, "offline")
	}
}

func checkSSH(add func(string, string, Status, string)) {
	sshPath, _ := util.SSHPath()
	configPath := filepath.Join(sshPath, "config")
	include := "Include " + util.SSHConfigFile()

	content, err := os.ReadFile(filepath.Clean(configPath))
	switch {
	case err != nil:
		add("SSH", "~/.ssh/config", StatusWarn, err.Error())
	case !strings.Contains(string(content), include):
		add("SSH", "~/.ssh/config", StatusWarn,
			fmt.Sprintf("missing %q (run nk login)", include))
	default:
		add("SSH", "~/.ssh/config", StatusOK, "include directive present")
	}

	managed := util.SSHConfigFile()
	if hosts := countPrefix(managed, "Host "); hosts == 0 {
		add("SSH", "managed ssh_config", StatusInfo, "no hosts configured yet")
	} else {
		add("SSH", "managed ssh_config", StatusOK, fmt.Sprintf("%d host(s)", hosts))
	}

	knownHosts := util.KnownHostsPath()
	if cas := countPrefix(knownHosts, "@cert-authority"); cas == 0 {
		add("SSH", "known_hosts", StatusInfo, "no certificate authorities yet")
	} else {
		add("SSH", "known_hosts", StatusOK, fmt.Sprintf("%d @cert-authority entries", cas))
	}
}

func checkCerts(add func(string, string, Status, string), s *state.State) {
	certs, err := util.SSHCertificates()
	if err != nil {
		add("Certificates", "local certificates", StatusFail, err.Error())
		return
	}
	if len(certs) == 0 {
		add("Certificates", "local certificates", StatusInfo, "none issued yet")
		return
	}

	now := time.Now()
	const warnWindow = time.Hour
	for _, path := range certs {
		name := certID(path)
		ca := s.GetCAByID(name)
		if ca != nil {
			name = ca.Name
		}

		// A local cert for a CA that is no longer configured is stale clutter.
		if ca == nil {
			add("Certificates", name, StatusWarn,
				"stale file, no matching CA (run nk doctor --fix to remove)")
			continue
		}

		data, readErr := os.ReadFile(filepath.Clean(path))
		if readErr != nil {
			add("Certificates", name, StatusFail, "unreadable certificate file")
			continue
		}
		validAfter, validBefore, parseErr := ssh.CertificateValidity(data)
		if parseErr != nil {
			add("Certificates", name, StatusFail, "invalid certificate file")
			continue
		}

		switch {
		case now.Before(validAfter):
			add("Certificates", name, StatusWarn,
				"not yet valid until "+validAfter.Format(time.RFC3339))
		case now.After(validBefore):
			add("Certificates", name, StatusFail,
				"expired "+util.HumanizeDuration(now.Sub(validBefore))+" ago")
		case validBefore.Sub(now) < warnWindow:
			add("Certificates", name, StatusWarn,
				"expires in "+util.HumanizeDuration(validBefore.Sub(now)))
		default:
			add("Certificates", name, StatusOK,
				"expires in "+util.HumanizeDuration(validBefore.Sub(now)))
		}
	}
}

// repair fixes common issues and returns a human-readable list of what changed.
func repair(s *state.State) []string {
	var fixed []string

	if err := util.VerifyPaths(); err != nil {
		return append(fixed, "ensure paths: "+err.Error())
	}
	if err := ssh.GenerateSSHConfig(s); err != nil {
		fixed = append(fixed, "regenerate ssh_config: "+err.Error())
	} else {
		fixed = append(fixed, "regenerated "+util.SSHConfigFile())
	}
	if err := ssh.GenerateKnownHosts(s); err != nil {
		fixed = append(fixed, "regenerate known_hosts: "+err.Error())
	} else {
		fixed = append(fixed, "regenerated "+util.KnownHostsPath())
	}
	if runtime.GOOS != goosWindows {
		// #nosec G302 -- the config directory must remain owner-only.
		if err := os.Chmod(util.ConfigPath(), 0o700); err == nil {
			fixed = append(fixed, "chmod 0700 "+util.ConfigPath())
		}
		for _, f := range []string{
			util.ConfigFile(), util.CacheFile(), util.KeyFile(),
			util.PubKeyFile(), util.SSHConfigFile(), util.KnownHostsPath(),
		} {
			if util.FileExists(f) {
				if err := os.Chmod(f, 0o600); err == nil {
					fixed = append(fixed, "chmod 0600 "+f)
				}
			}
		}
	}

	return cleanStaleCerts(s, fixed)
}

// cleanStaleCerts removes local certificate files whose CA is not in cas.
func cleanStaleCerts(s *state.State, fixed []string) []string {
	certs, err := util.SSHCertificates()
	if err != nil || len(certs) == 0 {
		return fixed
	}
	if err = ssh.CleanupCerts(s.CAs); err != nil {
		return append(fixed, "clean stale certificates: "+err.Error())
	}
	return append(fixed, fmt.Sprintf("removed %d stale certificate(s)", len(certs)))
}

func certID(path string) string {
	return strings.TrimSuffix(filepath.Base(path), "-cert.pub")
}

func countPrefix(path, prefix string) int {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return 0
	}
	count := 0
	for line := range strings.SplitSeq(string(data), "\n") {
		if strings.HasPrefix(line, prefix) {
			count++
		}
	}
	return count
}

func sshBinary(ctx context.Context) (path, version string, ok bool) {
	path, err := exec.LookPath("ssh")
	if err != nil {
		return "", "", false
	}
	out, err := exec.CommandContext(ctx, path, "-V").CombinedOutput()
	if err != nil {
		return path, "OpenSSH", true
	}
	return path, strings.TrimSpace(string(out)), true
}
