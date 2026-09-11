package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nk/internal/client"
	nokkuv1 "github.com/nokku-sh/nk/internal/gen/nokku/v1"
	"github.com/nokku-sh/nk/internal/manual"
	"github.com/nokku-sh/nk/internal/state"
)

// hostKeyCommand prefers an ed25519 host key when the host has one.
const hostKeyCommand = `for t in ed25519 ecdsa rsa; do
  f=/etc/ssh/ssh_host_${t}_key.pub
  if [ -r "$f" ]; then cat "$f"; break; fi
done`

// remote runs commands with the system ssh, so the operator's own key, agent,
// and config apply.
type remote struct {
	host string
	user string
	port string
}

func targetCMD() *cli.Command {
	return &cli.Command{
		Name:     "target",
		Usage:    "Manage targets",
		Commands: []*cli.Command{syncCMD()},
	}
}

// syncCMD is wired as both `nk sync` and `nk target sync`.
func syncCMD() *cli.Command {
	return &cli.Command{
		Name:      "sync",
		Usage:     "Create a target if needed, then write its trust files onto the host",
		ArgsUsage: "<host | user@host>",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "name",
				Usage: "Target name. The server generates one when this is empty",
			},
			&cli.StringFlag{
				Name:  "workspace",
				Usage: "Workspace id or name, needed only when you belong to several",
			},
			&cli.StringFlag{
				Name:  "ca",
				Usage: "Certificate authority id or name, defaults to the workspace default",
			},
			&cli.BoolFlag{
				Name:  "dry-run",
				Usage: "Print the files a manual sync would write and change nothing",
			},
			&cli.StringFlag{
				Name:  "user",
				Usage: "SSH user a manual sync connects as",
				Value: "root",
			},
			&cli.StringFlag{
				Name:  "port",
				Usage: "SSH port a manual sync connects to",
				Value: "22",
			},
		},
		Action: targetSync,
	}
}

func targetSync(ctx context.Context, cmd *cli.Command) error {
	arg := cmd.Args().Get(0)
	if arg == "" {
		return errors.New("an ssh destination is required, for example: nk sync root@10.0.0.5")
	}

	c, s, err := connect(ctx, cmd, false)
	if err != nil {
		return err
	}

	workspace, err := resolveWorkspace(s, cmd.String("workspace"))
	if err != nil {
		return err
	}
	ca, caSource, err := resolveCA(s, workspace.ID, cmd.String("ca"))
	if err != nil {
		return err
	}

	// A known target name syncs that target, anything else is an ssh destination.
	sshUser := cmd.String("user")
	target := targetByName(s, workspace.ID, arg)
	if target == nil {
		dest := destination(arg, cmd.String("user"), cmd.IsSet("user"), cmd.String("port"))
		sshUser = dest.user
		target = targetByEndpoint(s, workspace.ID, dest.host)
		if target == nil && cmd.Bool("dry-run") {
			// A dry run previews the files without registering anything.
			target = &state.Target{
				WorkspaceID: workspace.ID,
				CAID:        ca.ID,
				Name:        cmd.String("name"),
				Endpoints:   []string{dest.host},
			}
		} else if target == nil {
			target, err = createTarget(ctx, c, workspace, ca, dest, cmd.String("name"))
			if err != nil {
				return err
			}
		}
	}

	if target.DaemonID != "" {
		return fmt.Errorf(
			"target %s has a daemon, which syncs itself. Run this on a daemonless target",
			target.Name,
		)
	}

	fmt.Printf("target %s in %s, ca %s (%s)\n",
		target.Name, workspace.Name, ca.Name, caSource)
	return syncManualTarget(ctx, cmd, c, s, target, sshUser)
}

func resolveWorkspace(s *state.State, ref string) (state.Workspace, error) {
	if ref != "" {
		for _, w := range s.Workspaces {
			if w.ID == ref || w.Name == ref {
				return w, nil
			}
		}
		return state.Workspace{}, fmt.Errorf("workspace %q not found", ref)
	}

	switch len(s.Workspaces) {
	case 0:
		return state.Workspace{}, errors.New("you do not belong to any workspace")
	case 1:
		return s.Workspaces[0], nil
	}

	names := make([]string, 0, len(s.Workspaces))
	for _, w := range s.Workspaces {
		names = append(names, w.Name)
	}
	return state.Workspace{}, fmt.Errorf(
		"you belong to several workspaces, pass --workspace: %s", strings.Join(names, ", "),
	)
}

// resolveCA picks the CA that signs a target's certificates and returns the
// source label shown in the sync header.
func resolveCA(s *state.State, workspaceID, ref string) (state.CA, string, error) {
	var candidates []state.CA
	for _, ca := range s.CAs {
		if ca.WorkspaceID == workspaceID {
			candidates = append(candidates, ca)
		}
	}

	if ref != "" {
		for _, ca := range candidates {
			if ca.ID == ref || ca.Name == ref {
				return ca, "selected", nil
			}
		}
		return state.CA{}, "", fmt.Errorf("certificate authority %q not found in this workspace", ref)
	}

	for _, ca := range candidates {
		if ca.Default {
			return ca, "default", nil
		}
	}

	switch len(candidates) {
	case 0:
		return state.CA{}, "", errors.New("this workspace has no certificate authority")
	case 1:
		return candidates[0], "only ca", nil
	}
	return state.CA{}, "", errors.New("this workspace has several certificate authorities, pass --ca")
}

func targetByName(s *state.State, workspaceID, name string) *state.Target {
	for i := range s.Targets {
		if s.Targets[i].WorkspaceID == workspaceID && s.Targets[i].Name == name {
			return &s.Targets[i]
		}
	}
	return nil
}

// targetByEndpoint skips daemon targets, which sync themselves.
func targetByEndpoint(s *state.State, workspaceID, host string) *state.Target {
	for i := range s.Targets {
		t := &s.Targets[i]
		if t.WorkspaceID != workspaceID || t.DaemonID != "" {
			continue
		}
		if slices.Contains(t.Endpoints, host) {
			return t
		}
	}
	return nil
}

// destination splits user@host, an explicit --user wins over it.
func destination(arg, user string, userSet bool, port string) remote {
	dest := remote{host: arg, user: user, port: port}
	if before, after, found := strings.Cut(arg, "@"); found {
		if before != "" && !userSet {
			dest.user = before
		}
		dest.host = after
	}
	return dest
}

// createTarget reads the host key over the operator's own ssh, so the pinned key
// means this host.
func createTarget(
	ctx context.Context,
	c *client.Client,
	workspace state.Workspace,
	ca state.CA,
	dest remote,
	name string,
) (*state.Target, error) {
	out, err := dest.run(ctx, hostKeyCommand)
	if err != nil {
		return nil, fmt.Errorf("read the host public key on %s: %w", dest.host, err)
	}
	hostKey := strings.TrimSpace(out)
	if hostKey == "" {
		return nil, fmt.Errorf("no host public key found on %s", dest.host)
	}

	created, err := c.CreateTarget(
		ctx, workspace.ID, ca.ID, strings.TrimSpace(name), hostKey, []string{dest.host},
	)
	if err != nil {
		return nil, err
	}
	fmt.Printf("created target %s for %s\n", created.GetName(), dest.host)

	return &state.Target{
		ID:            created.GetId(),
		WorkspaceID:   workspace.ID,
		CAID:          ca.ID,
		Name:          created.GetName(),
		Endpoints:     created.GetEndpoints(),
		HostPublicKey: created.GetHostPublicKey(),
	}, nil
}

func syncManualTarget(
	ctx context.Context,
	cmd *cli.Command,
	c *client.Client,
	s *state.State,
	target *state.Target,
	sshUser string,
) error {
	ca := s.CAByID(target.CAID)
	if ca == nil {
		return fmt.Errorf("target %s has no certificate authority %q", target.Name, target.CAID)
	}
	if strings.TrimSpace(ca.PublicKey) == "" {
		return fmt.Errorf("certificate authority %q has no public key", ca.Name)
	}

	host, port := manualAddress(target, cmd.String("port"), cmd.IsSet("port"))
	rd := remote{host: host, user: sshUser, port: port}

	// The first sync runs before the host trusts Nokku, so use the operator's own ssh.
	passwd, err := rd.run(ctx, "getent passwd")
	if err != nil {
		return fmt.Errorf("list local accounts on %s: %w", host, err)
	}
	accounts := manual.LocalAccounts(passwd)

	hostKey, err := rd.run(ctx, hostKeyCommand)
	if err != nil {
		return fmt.Errorf("read the host public key on %s: %w", host, err)
	}
	hostKey = strings.TrimSpace(hostKey)
	if hostKey == "" {
		return fmt.Errorf("no host public key found on %s", host)
	}

	principals, err := c.GetTargetPrincipals(ctx, target.WorkspaceID, target.ID)
	if err != nil {
		return err
	}
	existing, err := rd.run(ctx, manual.PrincipalsListCommand)
	if err != nil {
		return fmt.Errorf("list principal files on %s: %w", host, err)
	}

	files := manual.HostFiles(ca.PublicKey, grantsByUser(principals), accounts)
	stale := manual.StalePrincipals(strings.Fields(existing), accounts)

	if cmd.Bool("dry-run") {
		fmt.Println("Dry run, nothing written")
		for _, f := range files {
			fmt.Printf("\n%s (%04o)\n%s", f.Path, f.Mode, f.Content)
		}
		for _, path := range stale {
			fmt.Printf("\nremoved %s\n", path)
		}
		return nil
	}

	// Backend writes, which the dry run above skips.
	if err = c.SyncTargetUsers(ctx, target.WorkspaceID, target.ID, accounts, hostKey, target.Endpoints); err != nil {
		return err
	}

	out, err := rd.runScript(ctx, manual.WriteScript(files, stale))
	fmt.Print(out)
	if err != nil {
		return err
	}

	// A host without systemd reloads sshd by hand.
	if !manual.Reloaded(out) {
		fmt.Fprintln(os.Stderr, "warning: sshd was not reloaded, reload it to apply the drop-in")
	}

	if grantedRoot(principals) {
		warnRootLogin(ctx, rd)
	}
	return nil
}

func grantsByUser(principals []*nokkuv1.PrincipalUsers) map[string][]string {
	grants := make(map[string][]string, len(principals))
	for _, p := range principals {
		grants[p.GetUsername()] = p.GetIds()
	}
	return grants
}

func grantedRoot(principals []*nokkuv1.PrincipalUsers) bool {
	for _, p := range principals {
		if p.GetUsername() == "root" {
			return true
		}
	}
	return false
}

// Root login policy is the operator's call, so this only warns.
func warnRootLogin(ctx context.Context, rd remote) {
	cfg, err := rd.run(ctx, "sshd -T")
	if err != nil || manual.RootLoginAllowed(cfg) {
		return
	}
	fmt.Fprintln(os.Stderr, "warning: root is granted certificate login but sshd does not allow it")
	fmt.Fprintln(os.Stderr, "         set PermitRootLogin prohibit-password (or yes) on the host")
}

// manualAddress bypasses the Nokku proxy, which cannot authenticate yet.
func manualAddress(target *state.Target, port string, portSet bool) (host, resolvedPort string) {
	if len(target.Endpoints) == 0 {
		return target.Name, port
	}
	host, resolvedPort = target.Endpoints[0], port
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		if p != "" && !portSet {
			resolvedPort = p
		}
	}
	return host, resolvedPort
}

func (r remote) run(ctx context.Context, command string) (string, error) {
	return r.exec(ctx, command, "")
}

func (r remote) runScript(ctx context.Context, script string) (string, error) {
	return r.exec(ctx, "sh -s", script)
}

func (r remote) exec(ctx context.Context, command, stdin string) (string, error) {
	args := []string{"-o", "BatchMode=yes"}
	if r.port != "" {
		args = append(args, "-p", r.port)
	}
	// -- keeps a destination that starts with - from being read as an ssh flag.
	args = append(args, "-l", r.user, "--", r.host, command)

	cmd := exec.CommandContext(ctx, "ssh", args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = strings.TrimSpace(stdout.String())
		}
		return stdout.String(), fmt.Errorf("ssh %s: %w: %s", r.host, err, detail)
	}
	return stdout.String(), nil
}
