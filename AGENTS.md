# nk

nk is the Nokku CLI: login and cert minting, generated ssh config, the
operator-driven manual sync for daemonless targets, and the hidden proxy
command behind every ssh connection. The ecosystem is five sibling repos:
`nokku` (backend), `nokkud` (edge daemon), `nk` (this one), `mon` (shared
primitives), and `protos` (proto source). Read `../nokku/docs/PRODUCT.md`
before cross-repo work.

## Commands

```bash
task build    # installs to ~/.local/bin
task gen      # buf generate
task lint     # tidy, fmt, vet, govulncheck, test -race, golangci-lint
task fuzz     # every Fuzz target, FUZZTIME=30s default
```

Plain `go test ./...` works.

## Layout

- `main.go` - entrypoint.
- `internal/cmd` - every command. `target.go` holds the manual sync flow,
  `proxy.go` the hidden ProxyCommand entry.
- `internal/client` - all RPCs go through here. DPoP client, cert minting,
  sync.
- `internal/state` - persisted config and offline cache, mapped from proto
  to plain structs.
- `internal/ssh` - ssh key setup, generated `ssh_config` and `known_hosts`.
- `internal/manual` - pure renderer for the manual-sync host files and write
  script. No I/O by design.
- `internal/doctor` - diagnostics. `internal/ui` - terminal output helpers.
- `internal/paths`, `internal/pki` - filesystem locations, X.509.
- `internal/gen` - generated proto code. Never hand-edit.

## Conventions

- All RPCs go through `internal/client`. Commands never build connect
  clients themselves.
- `ssh_config` and `known_hosts` are generated files. Regenenerate, never
  hand-edit or hand-merge.
- `nk proxy` is the hidden ProxyCommand entry. ssh invokes it, users do not.
- `internal/manual` is a pure renderer with no I/O by design. Keep it that
  way, it is what makes the write script testable.
- Manual sync runs over the operator's own system ssh. Never add an embedded
  ssh client or credentials for it.
- Machine identity uses the `nokku-cli` and `nokku-cli-ssh` salts from the
  registry in `../mon/README.md`.

## Danger points

- Never write credentials into the generated ssh files.
