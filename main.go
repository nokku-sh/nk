package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/mizuchilabs/kata/buildinfo"
	"github.com/mizuchilabs/kata/sigx"
	altsrc "github.com/urfave/cli-altsrc/v3"
	json "github.com/urfave/cli-altsrc/v3/json"
	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nk/internal/api"
	"github.com/nokku-sh/nk/internal/cert"
	nokkuv1 "github.com/nokku-sh/nk/internal/gen/nokku/v1"
	"github.com/nokku-sh/nk/internal/ssh"
	"github.com/nokku-sh/nk/internal/state"
	"github.com/nokku-sh/nk/internal/tpm"
	"github.com/nokku-sh/nk/internal/util"
)

func main() {
	cmd := &cli.Command{
		EnableShellCompletion: true,
		Suggest:               true,
		Name:                  "nk",
		Usage:                 "secure access, simplified",
		Version:               buildinfo.String(),
		Before: func(ctx context.Context, _ *cli.Command) (context.Context, error) {
			if err := util.VerifyPaths(); err != nil {
				return nil, err
			}
			return ctx, nil
		},
		Action: func(_ context.Context, cmd *cli.Command) error {
			s := state.New()
			s.APIURL = cmd.String("api")
			s.KeyType = cmd.String("key-type")
			if cmd.IsSet("token") {
				s.Token = cmd.String("token")
			}
			return s.Save()
		},
		Commands: []*cli.Command{
			{
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

					client, err := api.New(ctx, cmd)
					if err != nil {
						return err
					}

					if err = client.SignByTarget(ctx, host); err != nil {
						return err
					}

					// With a TPM identity the private key never touches disk:
					// serve it over the agent socket before ssh starts the
					// authentication phase through the proxy pipes.
					stopAgent, err := ssh.ServeAgent(ctx)
					if err != nil {
						return err
					}
					defer func() { _ = stopAgent() }()

					return ssh.Proxy(ctx, client.State, host, port)
				},
			},
			{
				Name:  "doctor",
				Usage: "Check local system setup and configuration",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					_, err := api.New(ctx, cmd)
					if err != nil {
						fmt.Printf("Failed to reach or authenticate with API: %v\n", err)
					} else {
						fmt.Println("API is reachable and authenticated.")
					}

					fmt.Printf("SSH identity: %s\n", ssh.IdentityStatus())
					if err = tpm.Available(); err != nil {
						fmt.Printf("TPM 2.0: unavailable (%v)\n", err)
						if errors.Is(err, os.ErrPermission) {
							fmt.Println(
								"hint: add your user to the tss group: sudo usermod -aG tss $USER",
							)
						}
					} else {
						fmt.Println("TPM 2.0: available")
					}

					sshPath, _ := util.SSHPath()
					path := sshPath + "/config"
					content, err := os.ReadFile(filepath.Clean(path))
					switch {
					case err != nil:
						fmt.Printf("Failed to read %s: %v\n", path, err)
					case !strings.Contains(string(content), "Include "+util.SSHConfigFile()):
						fmt.Printf("Include directive missing in %s\n", path)
					default:
						fmt.Println("Include directive found.")
					}

					configPath := util.ConfigPath()
					info, err := os.Stat(configPath)
					if err != nil {
						fmt.Printf("Failed to access %s: %v\n", configPath, err)
					} else {
						fmt.Printf(
							"Data directory %s exists (perms: %v).\n",
							configPath,
							info.Mode().Perm(),
						)
					}
					return nil
				},
			},
			{
				Name:    "list",
				Aliases: []string{"ls"},
				Usage:   "List available machines across all workspaces",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					client, err := api.New(ctx, cmd)
					if err != nil {
						return err
					}

					s := client.State
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
			},
			{
				Name:  "status",
				Usage: "Show current status",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					client, err := api.New(ctx, cmd)
					if err != nil {
						return err
					}
					s := client.State

					switch {
					case s.ServiceAccount != nil:
						fmt.Printf("Service account: %s\n", s.ServiceAccount.Name)
					case s.User != nil:
						fmt.Printf("Logged in as %s\n", s.User.Username)
					default:
						fmt.Println("Logged in (identity unknown)")
					}

					fmt.Printf("Workspaces (%d):\n", len(s.Workspaces))
					if len(s.Workspaces) > 0 {
						for _, w := range s.Workspaces {
							if strings.TrimSpace(w.Description) != "" {
								fmt.Printf("-  %s: %s\n", w.Name, w.Description)
							} else {
								fmt.Printf("-  %s\n", w.Name)
							}
						}
					}
					return nil
				},
			},
			{
				Name:  "cert",
				Usage: "Manage X.509 certificates (mTLS, databases, Kubernetes)",
				Commands: []*cli.Command{
					{
						Name:  "list",
						Usage: "List available X.509 certificate authorities",
						Action: func(ctx context.Context, cmd *cli.Command) error {
							client, err := api.New(ctx, cmd)
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
								return fmt.Errorf("common name is required")
							}
							if strings.ContainsAny(cn, `/\`) {
								return fmt.Errorf("common name must not contain path separators")
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

							client, err := api.New(ctx, cmd)
							if err != nil {
								return err
							}

							ca, err := resolveX509CA(ctx, client, cmd.String("ca"))
							if err != nil {
								return err
							}

							priv, err := cert.GenerateKey(cmd.String("key-type"))
							if err != nil {
								return err
							}
							csrPEM, err := cert.NewCSR(priv, cn, cmd.StringSlice("san"))
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

							if err = cert.WriteCert(
								certPath,
								[]byte(res.GetCertificate()),
							); err != nil {
								return err
							}
							if err = cert.WriteKey(keyPath, priv); err != nil {
								return err
							}
							if err = cert.WriteCert(caPath, []byte(res.GetCaChain())); err != nil {
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
			},
			{
				Name:    "login",
				Usage:   "Authenticate or refresh credentials",
				Aliases: []string{"refresh"},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					_, err := api.New(ctx, cmd)
					return err
				},
			},
			{
				Name:  "logout",
				Usage: "Logout and remove credentials",
				Action: func(_ context.Context, _ *cli.Command) error {
					state.New().Clear()
					util.CleanupPaths()
					fmt.Println("Cleaned up credentials")
					return nil
				},
			},
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "api",
				Usage: "Nokku API URL",
				Value: "https://app.nokku.sh",
				Sources: cli.NewValueSourceChain(
					cli.EnvVar("NK_API_URL"),
					json.JSON("api_url", altsrc.NewStringPtrSourcer(new(util.ConfigFile()))),
				),
			},
			&cli.StringFlag{
				Name:    "token",
				Usage:   "Service account token (skips browser login, for CI/CD); never stored on disk",
				Sources: cli.EnvVars("NK_TOKEN"),
			},
			&cli.StringFlag{
				Name:  "key-type",
				Usage: "SSH key algorithm (ed25519, rsa-2048, rsa-4096, ecdsa-p256, ecdsa-p384, ecdsa-p521, tpm)",
				Value: "ed25519",
				Sources: cli.NewValueSourceChain(
					cli.EnvVar("NK_KEY_TYPE"),
					json.JSON("key_type", altsrc.NewStringPtrSourcer(new(util.ConfigFile()))),
				),
				Action: func(_ context.Context, _ *cli.Command, val string) error {
					if !slices.Contains(ssh.ValidKeyTypes, ssh.KeyType(val)) {
						return fmt.Errorf(
							"invalid --key-type %q. Allowed choices are: %v",
							val,
							ssh.ValidKeyTypes,
						)
					}
					return nil
				},
			},
			&cli.DurationFlag{
				Name:    "ttl",
				Usage:   "Certificate TTL",
				Sources: cli.EnvVars("NK_TTL"),
			},
			&cli.BoolFlag{
				Name:    "require-tpm",
				Usage:   "Require a TPM 2.0 for request signing, refuse the software fallback key",
				Sources: cli.EnvVars("NK_REQUIRE_TPM"),
			},
			&cli.BoolFlag{
				Name:    "insecure",
				Usage:   "Disable TLS verification",
				Sources: cli.EnvVars("NK_INSECURE"),
			},
		},
	}

	if err := cmd.Run(sigx.NotifyContext(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", cmd.Name, err)
		os.Exit(1)
	}
}

// resolveX509CA finds an X.509 CA by ID or name. When nameOrID is empty
// and exactly one X.509 CA exists, it is used by default.
func resolveX509CA(
	ctx context.Context,
	client *api.Client,
	nameOrID string,
) (*nokkuv1.CertificateAuthority, error) {
	cas, err := client.ListX509CAs(ctx)
	if err != nil {
		return nil, err
	}
	return cert.MatchX509CA(cas, nameOrID)
}
