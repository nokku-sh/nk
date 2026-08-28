package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nk/internal/api"
	"github.com/nokku-sh/nk/internal/doctor"
	nokkuv1 "github.com/nokku-sh/nk/internal/gen/nokku/v1"
	"github.com/nokku-sh/nk/internal/pki"
	"github.com/nokku-sh/nk/internal/ssh"
	"github.com/nokku-sh/nk/internal/state"
	"github.com/nokku-sh/nk/internal/util"
)

const (
	jsonFlag    = "json"
	jsonFlagUse = "Output machine-readable JSON"
)

var Commands = []*cli.Command{
	loginCMD(),
	logoutCMD(),
	proxyCMD(),
	listCMD(),
	doctorCMD(),
	pkiCMD(),
}

func loginCMD() *cli.Command {
	return &cli.Command{
		Name:    "login",
		Usage:   "Authenticate or refresh credentials",
		Aliases: []string{"refresh"},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			_, err := api.Connect(ctx, state.FromCommand(cmd))
			return err
		},
	}
}

func logoutCMD() *cli.Command {
	return &cli.Command{
		Name:  "logout",
		Usage: "Logout and remove credentials",
		Action: func(_ context.Context, _ *cli.Command) error {
			util.CleanupPaths()
			fmt.Println("Cleaned up credentials")
			return nil
		},
	}
}

func proxyCMD() *cli.Command {
	return &cli.Command{
		Name:      "proxy",
		Usage:     "Proxy an SSH connection (internal use by SSH)",
		ArgsUsage: "[host] [port]",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			host := cmd.Args().Get(0)
			if host == "" {
				return fmt.Errorf("host name is required")
			}
			port := cmd.Args().Get(1)
			if port == "" {
				port = "22"
			}

			// The proxy path is deliberately lightweight: it loads cached
			// state (no sync), resolves the target, and only signs a
			// certificate when it is missing or close to expiry.
			s := state.FromCommand(cmd)
			client, err := api.New(ctx, s)
			if err != nil {
				return err
			}

			target, err := ssh.ResolveTarget(s, host)
			if err != nil {
				return err
			}
			if err = client.SignTarget(ctx, target); err != nil {
				if !ssh.CertificateOnDisk(target.CAID) {
					return err
				}
				slog.Warn("certificate signing failed, using cached certificate",
					"target", target.Name, "err", err)
			}

			// Serve the TPM key over the agent socket before ssh starts the
			// authentication phase.
			stopAgent, err := ssh.ServeAgent(ctx)
			if err != nil {
				return err
			}
			defer func() { _ = stopAgent() }()

			return ssh.Proxy(ctx, target, port)
		},
	}
}

func doctorCMD() *cli.Command {
	return &cli.Command{
		Name:  "doctor",
		Usage: "Check local system setup and configuration",
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: jsonFlag, Usage: jsonFlagUse},
			&cli.BoolFlag{
				Name:  "fix",
				Usage: "Repair common issues (ssh config, permissions)",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			report := doctor.RunDoctor(
				ctx,
				state.FromCommand(cmd),
				cmd.Bool("fix"),
			)
			if err := doctor.PrintReport(os.Stdout, report, cmd.Bool(jsonFlag)); err != nil {
				return err
			}
			if code := report.ExitCode(); code != 0 {
				return cli.Exit("", code)
			}
			return nil
		},
	}
}

func listCMD() *cli.Command {
	return &cli.Command{
		Name:    "list",
		Aliases: []string{"ls"},
		Usage:   "List available machines across all workspaces",
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: jsonFlag, Usage: jsonFlagUse},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			client, err := api.Connect(ctx, state.FromCommand(cmd))
			if err != nil {
				return err
			}

			s := client.State
			if cmd.Bool(jsonFlag) {
				return printTargetsJSON(s)
			}
			if len(s.Targets) == 0 {
				fmt.Println("No targets available.")
				return nil
			}

			fmt.Printf("Targets (%d):\n", len(s.Targets))
			for _, t := range s.Targets {
				users := make([]string, 0, len(t.Principals))
				for _, p := range t.Principals {
					users = append(users, p.Username)
				}
				userStr := "none"
				if len(users) > 0 {
					userStr = strings.Join(users, ", ")
				}
				fmt.Printf("-  %-20s  [Users: %s]\n", t.Name, userStr)
			}
			fmt.Println("Connect using: ssh <target-name> or ssh <user>@<target-name>")
			return nil
		},
	}
}

//nolint:funlen // TODO
func pkiCMD() *cli.Command {
	return &cli.Command{
		Name:  "pki",
		Usage: "Manage X.509 certificates (mTLS, databases, Kubernetes)",
		Commands: []*cli.Command{
			{
				Name:  "list",
				Usage: "List available X.509 certificate authorities",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					client, err := api.Connect(ctx, state.FromCommand(cmd))
					if err != nil {
						return err
					}

					cas, err := client.ListX509CAs(ctx)
					if err != nil {
						return err
					}
					if len(cas) == 0 {
						fmt.Println("No X.509 certificate authorities available.")
						return nil
					}

					fmt.Printf("X.509 Certificate Authorities (%d):\n", len(cas))
					for _, ca := range cas {
						fmt.Printf(
							"-  %-24s  %s  (expires %s)\n",
							ca.GetName(),
							ca.GetId(),
							ca.GetNotAfter().AsTime().Format(time.DateOnly),
						)
					}
					return nil
				},
			},
			{
				Name:      "issue",
				Usage:     "Issue an X.509 certificate",
				ArgsUsage: "<common-name>",
				Flags: []cli.Flag{
					&cli.StringSliceFlag{
						Name:  "san",
						Usage: "Subject alternative name (dns:name, ip:addr, email:addr, uri:uri, or bare value to auto-detect)",
					},
					&cli.StringFlag{
						Name:  "usage",
						Usage: "Certificate usage: client, server, or both",
						Value: "client",
					},
					&cli.StringFlag{
						Name:  "ca",
						Usage: "CA ID or name (optional when only one X.509 CA exists)",
					},
					&cli.StringFlag{
						Name:    "output",
						Aliases: []string{"o"},
						Usage:   "Output directory",
						Value:   ".",
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					cn := cmd.Args().Get(0)
					if cn == "" {
						return errors.New("common name is required")
					}
					if strings.ContainsAny(cn, `/\`) {
						return errors.New("common name must not contain path separators")
					}

					var usage nokkuv1.SignX509CertificateRequest_X509Usage
					switch strings.ToLower(cmd.String("usage")) {
					case "client":
						usage = nokkuv1.SignX509CertificateRequest_X509_USAGE_CLIENT_AUTH
					case "server":
						usage = nokkuv1.SignX509CertificateRequest_X509_USAGE_SERVER_AUTH
					case "both":
						usage = nokkuv1.SignX509CertificateRequest_X509_USAGE_CLIENT_AND_SERVER
					default:
						return fmt.Errorf(
							"invalid usage %q (expected client, server, or both)",
							cmd.String("usage"),
						)
					}

					client, err := api.Connect(ctx, state.FromCommand(cmd))
					if err != nil {
						return err
					}
					cas, err := client.ListX509CAs(ctx)
					if err != nil {
						return err
					}
					ca, err := pki.MatchCA(cas, cmd.String("ca"))
					if err != nil {
						return err
					}

					priv, err := pki.GenerateKey()
					if err != nil {
						return err
					}
					csrPEM, err := pki.NewCSR(priv, cn, cmd.StringSlice("san"))
					if err != nil {
						return err
					}

					res, err := client.SignX509Certificate(
						ctx,
						ca,
						csrPEM,
						usage,
						cmd.Duration("ttl"),
					)
					if err != nil {
						return err
					}

					dir := cmd.String("output")
					if err = os.MkdirAll(dir, 0o750); err != nil {
						return err
					}
					certPath := filepath.Join(dir, cn+".crt")
					keyPath := filepath.Join(dir, cn+".key")
					caPath := filepath.Join(dir, cn+"-ca.crt")

					if err = pki.WriteCert(certPath, []byte(res.GetCertificate())); err != nil {
						return err
					}
					if err = pki.WriteKey(keyPath, priv); err != nil {
						return err
					}
					if err = pki.WriteCert(caPath, []byte(res.GetCaChain())); err != nil {
						return err
					}

					fmt.Printf("Certificate issued by %q (expires %s)\n",
						ca.GetName(), res.GetExpiresAt().AsTime().Format(time.RFC3339))
					fmt.Printf(
						"  cert: %s\n  key:  %s\n  ca:   %s\n",
						certPath,
						keyPath,
						caPath,
					)
					return nil
				},
			},
		},
	}
}

// printTargetsJSON writes the machine list as JSON, grouped by workspace.
func printTargetsJSON(s *state.State) error {
	workspaces := make(map[string]string, len(s.Workspaces))
	for _, w := range s.Workspaces {
		workspaces[w.ID] = w.Name
	}

	type target struct {
		Name      string   `json:"name"`
		Workspace string   `json:"workspace"`
		Users     []string `json:"users"`
	}
	out := struct {
		Targets []target `json:"targets"`
	}{Targets: make([]target, 0, len(s.Targets))}

	for _, t := range s.Targets {
		users := make([]string, 0, len(t.Principals))
		for _, p := range t.Principals {
			users = append(users, p.Username)
		}
		out.Targets = append(out.Targets, target{
			Name:      t.Name,
			Workspace: workspaces[t.WorkspaceID],
			Users:     users,
		})
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}
