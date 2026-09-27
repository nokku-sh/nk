package cmd

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nk/internal/client"
	"github.com/nokku-sh/nk/internal/manual"
	"github.com/nokku-sh/nk/internal/paths"
	"github.com/nokku-sh/nk/internal/state"
	"github.com/nokku-sh/nk/internal/ui"
)

func syncCMD() *cli.Command {
	return &cli.Command{
		Name:  "sync",
		Usage: "Add a server to Nokku without the daemon, or refresh one you added",
		Description: "Connects as root with your own ssh, then writes the Nokku CA, an sshd drop-in, " +
			"and one principals file per account. Run it again whenever access changes.",
		ArgsUsage: "<host | root@host | target-name>",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "name", Usage: "Name for a new target, generated when empty"},
			&cli.StringFlag{Name: "workspace", Usage: "Workspace id or name, needed only when you belong to several"},
			&cli.StringFlag{
				Name:  "ca",
				Usage: "Certificate authority id or name for a new target, defaults to the workspace default",
			},
			&cli.StringFlag{Name: "port", Usage: "SSH port of the server, defaults to your ssh config or 22"},
			&cli.BoolFlag{Name: "dry-run", Usage: "Show what would be written and change nothing"},
		},
		Action: targetSync,
	}
}

func targetSync(ctx context.Context, cmd *cli.Command) error {
	arg := cmd.Args().First()
	if arg == "" {
		return errors.New("which server? For example: nk sync 10.0.0.5")
	}
	user, host, found := strings.Cut(arg, "@")
	if !found {
		host, user = arg, "root"
	}
	if user != "root" {
		return fmt.Errorf("nk sync connects as root, use root@%s", host)
	}

	c, err := connect(ctx, cmd, true)
	if err != nil {
		return err
	}
	s := c.State
	dryRun := cmd.Bool("dry-run")

	target, err := findTarget(s, cmd.String("workspace"), host)
	if err != nil {
		return err
	}
	dest := remote{host: host, port: cmd.String("port")}
	if target == nil {
		if target, err = newTarget(ctx, s, cmd, dest); err != nil {
			return err
		}
	} else if target.Name == host && len(target.Endpoints) > 0 {
		// Reached by name, so connect to where the target lives.
		dest = endpointRemote(target.Endpoints[0], dest.port)
	}
	ca := s.CAByID(target.CAID)
	if ca == nil || strings.TrimSpace(ca.PublicKey) == "" {
		return fmt.Errorf("the certificate authority of %s is missing, run nk login and try again", target.Name)
	}

	fmt.Printf("Connecting with: %s\n", dest)
	out, err := dest.run(ctx, manual.ProbeCommand, "")
	if err != nil {
		return err
	}
	h, err := manual.ParseProbe(out)
	if err != nil {
		return fmt.Errorf("%s: %w", dest.host, err)
	}
	if target.HostPublicKey != "" && target.HostPublicKey != h.HostKey {
		warnf("the host key of %s changed since the last sync, users will trust the new one", dest.host)
	}

	grants := map[string][]string{}
	if target.ID == "" && !dryRun {
		target.HostPublicKey = h.HostKey
		if target, err = c.CreateTarget(ctx, target); err != nil {
			return err
		}
		fmt.Printf("Added target %s\n", ui.Bold(target.Name))
	}
	if target.ID != "" {
		if grants, err = c.TargetPrincipals(ctx, target); err != nil {
			return err
		}
	}
	plan := manual.NewPlan(ca.PublicKey, grants, h)

	if dryRun {
		fmt.Println("Dry run, nothing was written. This sync would write:")
		for _, f := range plan.Files {
			fmt.Printf("\n%s\n%s", ui.Bold(f.Path), cmp.Or(f.Content, ui.Dim("(empty, nobody may log in)\n")))
		}
		for _, path := range plan.Stale {
			fmt.Printf("\n%s %s\n", ui.Bold("remove"), path)
		}
		return nil
	}

	return applyPlan(ctx, c, target, dest, h, plan)
}

// applyPlan writes the host first and reports to Nokku only once that worked.
func applyPlan(
	ctx context.Context,
	c *client.Client,
	target *state.Target,
	dest remote,
	h manual.Host,
	plan manual.Plan,
) error {
	out, err := dest.run(ctx, "sh -s", plan.Script())
	fmt.Print(ui.Dim(manual.Output(out)))
	if err != nil {
		return fmt.Errorf("writing to %s failed, nothing was reported to Nokku: %w", dest.host, err)
	}
	if err = c.ReportTarget(ctx, target, h.Accounts, h.HostKey); err != nil {
		return fmt.Errorf("the host is up to date, but reporting to Nokku failed, run nk sync again: %w", err)
	}

	res := manual.ParseResult(out)
	if !res.Reloaded {
		warnf("could not reload sshd, restart it on the host to apply the changes")
	}
	if !res.Verified {
		warnf("sshd is not using the Nokku drop-in. Make sure /etc/ssh/sshd_config has\n" +
			"  Include /etc/ssh/sshd_config.d/*.conf\nnear the top, then run nk sync again")
	}

	// Refresh locally so nk ls, ssh_config, and the host key pin match at once.
	if err = c.SyncOrCache(ctx, false); err != nil {
		warnf("local refresh failed, run nk login to update your ssh config")
	}
	fmt.Printf("%s %s is synced. Users connect with: ssh <user>@%s\n", ui.Green("✔"), target.Name, target.Name)
	return nil
}

// findTarget looks for an existing manual target by name or endpoint.
func findTarget(s *state.State, workspace, host string) (*state.Target, error) {
	var matches []*state.Target
	for i := range s.Targets {
		t := &s.Targets[i]
		if workspace != "" && t.WorkspaceID != workspace && s.WorkspaceName(t.WorkspaceID) != workspace {
			continue
		}
		if t.Name == host ||
			slices.ContainsFunc(t.Endpoints, func(ep string) bool { return endpointHost(ep) == host }) {
			matches = append(matches, t)
		}
	}
	switch {
	case len(matches) == 0:
		return nil, nil //nolint:nilnil // no match means a new server
	case len(matches) > 1:
		return nil, fmt.Errorf("%s matches targets in several workspaces, pass --workspace", host)
	case !matches[0].Manual():
		return nil, fmt.Errorf("%s runs the Nokku daemon, which keeps itself in sync", matches[0].Name)
	}
	return matches[0], nil
}

// newTarget prepares a target for a server Nokku does not know yet. It is
// created on the backend only once the host key is read.
func newTarget(ctx context.Context, s *state.State, cmd *cli.Command, dest remote) (*state.Target, error) {
	ws, err := resolveWorkspace(s, cmd.String("workspace"))
	if err != nil {
		return nil, err
	}
	ca, err := resolveCA(s, ws.ID, cmd.String("ca"))
	if err != nil {
		return nil, err
	}
	// Users dial the endpoint directly, so store the real address behind an
	// alias from the operator's ssh config.
	addr := dest.resolve(ctx)
	endpoint := addr.host
	if addr.port != "" && addr.port != "22" {
		endpoint = net.JoinHostPort(addr.host, addr.port)
	}
	return &state.Target{
		WorkspaceID: ws.ID,
		CAID:        ca.ID,
		Name:        strings.TrimSpace(cmd.String("name")),
		Endpoints:   []string{endpoint},
	}, nil
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
		return state.Workspace{}, errors.New("you do not belong to any workspace yet")
	case 1:
		return s.Workspaces[0], nil
	}
	names := make([]string, 0, len(s.Workspaces))
	for _, w := range s.Workspaces {
		names = append(names, w.Name)
	}
	return state.Workspace{}, fmt.Errorf(
		"you belong to several workspaces, pass --workspace with one of: %s",
		strings.Join(names, ", "),
	)
}

// resolveCA picks the named CA, else the workspace default, else the only one.
func resolveCA(s *state.State, workspaceID, ref string) (state.CA, error) {
	var cas []state.CA
	for _, ca := range s.CAs {
		if ca.WorkspaceID == workspaceID {
			cas = append(cas, ca)
		}
	}
	if i := slices.IndexFunc(cas, func(ca state.CA) bool {
		return ref != "" && (ca.ID == ref || ca.Name == ref) || ref == "" && ca.Default
	}); i >= 0 {
		return cas[i], nil
	}
	switch {
	case ref != "":
		return state.CA{}, fmt.Errorf("certificate authority %q not found in this workspace", ref)
	case len(cas) == 1:
		return cas[0], nil
	case len(cas) == 0:
		return state.CA{}, errors.New("this workspace has no certificate authority yet, create one in the Nokku UI")
	}
	return state.CA{}, errors.New("this workspace has several certificate authorities, pass --ca")
}

func endpointHost(ep string) string {
	if h, _, err := net.SplitHostPort(ep); err == nil {
		return h
	}
	return ep
}

// endpointRemote uses the endpoint's own port unless --port was set.
func endpointRemote(ep, port string) remote {
	r := remote{host: ep, port: port}
	if h, p, err := net.SplitHostPort(ep); err == nil {
		r.host = h
		r.port = cmp.Or(port, p)
	}
	return r
}

// remote runs commands as root with the system ssh, so the operator's own
// keys, agent, and config apply.
type remote struct {
	host string
	port string
}

func (r remote) String() string {
	if r.port == "" || r.port == "22" {
		return "ssh root@" + r.host
	}
	return "ssh -p " + r.port + " root@" + r.host
}

// portArgs leaves the port to the operator's ssh config unless one was given.
func (r remote) portArgs() []string {
	if r.port == "" {
		return nil
	}
	return []string{"-p", r.port}
}

// resolve asks ssh which host and port an alias from the operator's ssh
// config points at, without connecting.
func (r remote) resolve(ctx context.Context) remote {
	//nolint:gosec // argv, not a shell, and -- ends the options
	out, err := exec.CommandContext(ctx, "ssh", append(r.portArgs(), "-G", "--", r.host)...).Output()
	if err != nil {
		return r
	}
	for line := range strings.SplitSeq(string(out), "\n") {
		switch k, v, _ := strings.Cut(strings.TrimSpace(line), " "); k {
		case "hostname":
			r.host = v
		case "port":
			r.port = v
		}
	}
	return r
}

func (r remote) run(ctx context.Context, command, stdin string) (string, error) {
	args := append(r.portArgs(), "-l", "root",
		// Like answering yes on first contact, a changed key is still refused.
		"-o", "StrictHostKeyChecking=accept-new",
	)
	if runtime.GOOS != "windows" {
		// Share one connection, so a password or key prompt comes only once.
		args = append(args,
			"-o", "ControlMaster=auto",
			"-o", `ControlPath="`+filepath.Join(paths.ConfigPath(), "cm-%C")+`"`,
			"-o", "ControlPersist=30s",
		)
	}
	// -- keeps a host that starts with - from being read as a flag.
	args = append(args, "--", r.host, command)

	cmd := exec.CommandContext(ctx, "ssh", args...)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Stderr = os.Stderr
	var out strings.Builder
	cmd.Stdout = &out
	err := cmd.Run()
	if ee, ok := errors.AsType[*exec.ExitError](err); ok && ee.ExitCode() == 255 {
		return out.String(), fmt.Errorf("could not connect as root, check that this works: %s", r)
	}
	return out.String(), err
}
