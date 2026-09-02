package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nk/internal/client"
	nokkuv1 "github.com/nokku-sh/nk/internal/gen/nokku/v1"
	"github.com/nokku-sh/nk/internal/pki"
	"github.com/nokku-sh/nk/internal/state"
)

func pkiCMD() *cli.Command {
	return &cli.Command{
		Name:  "pki",
		Usage: "Manage X.509 certificates (mTLS, databases, Kubernetes)",
		Commands: []*cli.Command{
			{
				Name:  "list",
				Usage: "List available X.509 certificate authorities",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: jsonFlag, Usage: jsonFlagUse},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					client, err := connectForJIT(ctx, cmd)
					if err != nil {
						return err
					}

					cas, err := client.ListX509CAs(ctx)
					if err != nil {
						return err
					}
					if cmd.Bool(jsonFlag) {
						return printCAsJSON(cas)
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
				Action: pkiIssue,
			},
		},
	}
}

// pkiIssue generates a key pair and CSR, has it signed by the selected CA,
// and writes the certificate, private key, and CA chain to the output dir.
func pkiIssue(ctx context.Context, cmd *cli.Command) error {
	cn := cmd.Args().Get(0)
	if cn == "" {
		return errors.New("common name is required")
	}
	if strings.ContainsAny(cn, `/\`) {
		return errors.New("common name must not contain path separators")
	}

	usage, err := parseX509Usage(cmd.String("usage"))
	if err != nil {
		return err
	}

	client, err := connectForJIT(ctx, cmd)
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
}

func parseX509Usage(s string) (nokkuv1.SignX509CertificateRequest_X509Usage, error) {
	switch strings.ToLower(s) {
	case "client":
		return nokkuv1.SignX509CertificateRequest_X509_USAGE_CLIENT_AUTH, nil
	case "server":
		return nokkuv1.SignX509CertificateRequest_X509_USAGE_SERVER_AUTH, nil
	case "both":
		return nokkuv1.SignX509CertificateRequest_X509_USAGE_CLIENT_AND_SERVER, nil
	default:
		return 0, fmt.Errorf("invalid usage %q (expected client, server, or both)", s)
	}
}

// connectForJIT builds a client and syncs access just in time, falling back
// to cached data when the backend is unreachable.
func connectForJIT(ctx context.Context, cmd *cli.Command) (*client.Client, error) {
	s := state.FromCommand(cmd)
	client, err := client.New(s)
	if err != nil {
		return nil, err
	}
	err = client.SyncOrCache(ctx, true)
	if err != nil {
		return nil, err
	}
	return client, nil
}

type caJSON struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	ExpiresAt string `json:"expires_at"`
}

func printCAsJSON(cas []*nokkuv1.CertificateAuthority) error {
	out := struct {
		CAs []caJSON `json:"cas"`
	}{CAs: make([]caJSON, 0, len(cas))}
	for _, ca := range cas {
		out.CAs = append(out.CAs, caJSON{
			ID:        ca.GetId(),
			Name:      ca.GetName(),
			ExpiresAt: ca.GetNotAfter().AsTime().Format(time.RFC3339),
		})
	}
	return printJSON(out)
}

func printJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}
