package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nk/internal/api"
	nokkuv1 "github.com/nokku-sh/nk/internal/gen/nokku/v1"
	"github.com/nokku-sh/nk/internal/pki"
)

//nolint:gocognit,funlen
func pkiCommand() *cli.Command {
	return &cli.Command{
		Name:  "pki",
		Usage: "Manage X.509 certificates (mTLS, databases, Kubernetes)",
		Commands: []*cli.Command{
			{
				Name:  "list",
				Usage: "List available X.509 certificate authorities",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					client, err := api.Connect(ctx, cmd)
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

					client, err := api.Connect(ctx, cmd)
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
