module github.com/nokku-sh/nk

go 1.26.6

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.12-20260709200747-435963d16310.1
	connectrpc.com/connect v1.20.0
	connectrpc.com/grpchealth v1.5.0
	github.com/adrg/xdg v0.5.3
	github.com/cenkalti/backoff/v7 v7.0.0
	github.com/go-jose/go-jose/v4 v4.1.4
	github.com/google/go-tpm v0.9.8
	github.com/mizuchilabs/kagi v0.0.0-00010101000000-000000000000
	github.com/mizuchilabs/kata v0.1.3
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c
	github.com/urfave/cli-altsrc/v3 v3.1.0
	github.com/urfave/cli/v3 v3.11.0
	golang.org/x/crypto v0.55.0
	golang.org/x/sync v0.22.0
	golang.org/x/sys v0.47.0
	golang.org/x/term v0.45.0
	google.golang.org/genproto/googleapis/api v0.0.0-20260810153831-ec0a7760b754
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/google/go-tpm-tools v0.3.13-0.20230620182252-4639ecce2aba // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/mizuchilabs/kagi => /home/roxas/Projects/kagi
