<p align="center">
  <img src="./.github/logo.svg" height="80" alt="nk logo">
</p>

<p align="center">
  <a href="https://github.com/nokku-sh/nk/releases"><img src="https://img.shields.io/github/v/tag/nokku-sh/nk?label=Version" alt="Version"></a>
  <a href="https://github.com/nokku-sh/nk/blob/main/LICENSE"><img src="https://img.shields.io/github/license/nokku-sh/nk?label=License" alt="License"></a>
  <a href="https://github.com/nokku-sh/nk/actions"><img src="https://img.shields.io/github/actions/workflow/status/nokku-sh/nk/test.yaml?label=Build" alt="Build"></a>
</p>

# nk: The Nokku CLI

`nk` is your access portal. It signs you in, keeps your short-lived SSH certificates fresh, and seamlessly wires up your local configuration.

Our goal is top-tier Developer Experience (DX). You don't have to learn new custom SSH commands. Once authenticated, you connect to Nokku-managed servers using the plain OpenSSH you already know.

## Quick Start

Install the CLI:

```bash
curl -fsSL https://get.nokku.sh/nk | sh
```

On Linux the installer adds the Cloudsmith repository and installs your
distro's package (deb, rpm, apk). macOS, other distros and pinned versions
(`--version <x.y.z>` or `NK_VERSION=<x.y.z>`) get the release binary from
GitHub, in `~/.local/bin` or with `--system` in `/usr/local/bin`.

Prefer manual packages? See the [package repository](https://broadcasts.cloudsmith.com/nokku/nk) for apt/dnf/apk install instructions.

Authenticate via your browser and connect:

```bash
nk login          # Authenticate and sync your SSH config
nk ls             # List the targets you can access
ssh user@target   # Connect using standard OpenSSH!
```

> [!NOTE]
> Access is synced just in time: every `nk ls` refreshes what you can reach, and an SSH connection refreshes it when the last sync is more than a minute old. Revocations apply immediately, since the daemon enforces them on the server. When the backend is unreachable, `nk` fails fast and works from cached data and existing valid certificates. Direct addresses and the Nokku relay are tried in parallel, so an unreachable private address never slows a connection down.

## Hardware Security (TPM 2.0)

On Linux and Windows, `nk` automatically uses a TPM 2.0 when one is available. Your SSH private key becomes a deterministic primary key that never leaves the TPM; signing happens in a small background agent that `nk` starts on the first ssh connection and stops after 30 idle minutes. Without a TPM, `nk` falls back to a software ECDSA P-256 key wrapped with a key derived from the machine fingerprint: the state file is useless on another machine, and ssh reads the key only through the agent socket, never directly. Pass `--require-tpm` to refuse that fallback.

_(Check `nk doctor` to see if a TPM is available and in use.)_

> [!NOTE]
> On most Linux distributions `/dev/tpmrm0` is owned by `root:tss`, so regular users cannot use the TPM by default. Fix: `sudo usermod -aG tss $USER` and log in again (a udev rule granting your user access works too).

### Headless / CI

Use a service-account API key in CI or other headless environments:

```bash
export NK_TOKEN=nokku_sa_<SECRET>
nk login
ssh user@target
```

The `nokku_sa_` prefix is required, `nk` refuses any other token.

## X.509 certificates (experimental)

`nk` can also issue certificates for API clients, servers, and other workloads:

```bash
nk pki list
nk pki issue api-client --usage client --san dns:api.example.com
```

The command generates an ECDSA P-256 key pair (`--key-type ed25519` for ed25519), requests a signed certificate, and saves the certificate, private key, and CA certificate to the output directory. It never overwrites an existing key.

## Commands

| Command                      | Purpose                                                          |
| ---------------------------- | ---------------------------------------------------------------- |
| `nk login` (alias `refresh`) | Authenticate and synchronize local state                         |
| `nk ls` / `nk list`          | List available machines across all workspaces                    |
| `nk doctor`                  | Check API reachability, TPM availability, and local SSH setup    |
| `nk pki list`                | List active X.509 certificate authorities                        |
| `nk pki issue <cn>`          | Issue an X.509 certificate                                       |
| `nk sync <host>`             | Add a server without the daemon, or refresh one you added        |
| `nk target delete <host>`    | Clean up a server you added with `nk sync` and delete its target |
| `nk logout`                  | Sign out, stop the agent, and remove local credentials and state |

### Command flags

| Command            | Flags                                                                                   |
| ------------------ | --------------------------------------------------------------------------------------- |
| `nk ls`            | `--json` for machine-readable output                                                    |
| `nk doctor`        | `--fix` to repair permissions and regenerate files, `--json` for output                 |
| `nk pki list`      | `--json` for machine-readable output                                                    |
| `nk pki issue`     | `--san dns:name`, `--usage client\|server\|both`, `--ca`, `--key-type`, `--output`/`-o` |
| `nk sync`          | `--name`, `--workspace`, `--ca`, `--port`, `--dry-run`, `--accept-host-key`, `--json`   |
| `nk target delete` | `--workspace`, `--port`, `--keep-host` to leave the server untouched                    |

## Configuration

| Flag            | Environment         | Purpose                                                                   |
| --------------- | ------------------- | ------------------------------------------------------------------------- |
| `--api`         | `NK_API_URL`        | Backend URL                                                               |
|                 | `NK_TOKEN`          | Service-account key (`nokku_sa_...`) for CI/CD. Env only, never a flag    |
| `--ttl`         | `NK_TTL`            | Requested SSH certificate lifetime                                        |
| `--require-tpm` | `NK_REQUIRE_TPM`    | Require a TPM 2.0 or the Secure Enclave, refuse the software key fallback |
|                 | `NK_SECURE_ENCLAVE` | Set to `1` on macOS to keep new keys in the Secure Enclave. Experimental  |
| `--insecure`    | `NK_INSECURE`       | Disable TLS verification; testing only                                    |
| `--debug`       | `NK_DEBUG`          | Enable debug logging                                                      |

`--api` is remembered after the first use, so a self-hosted instance only needs
it once. Switching to another server drops the old session. The other flags
apply to one run only.

Local state lives under `~/.config/nk/` on every OS. Your private key and
tokens are credentials. Keep service-account tokens out of source control.

## Servers without the daemon

`nk sync` sets up a server you manage yourself, without installing `nokkud`:

```bash
nk sync 10.0.0.5            # or root@10.0.0.5, or an alias from ~/.ssh/config
nk sync web --dry-run       # show what would change on a known target
```

It connects as root with your own ssh, so your keys and ssh config apply and a
password is asked at most once. It writes the Nokku CA, an sshd drop-in, and one
principals file per account, checks the result with `sshd -t`, and rolls every
file back if sshd rejects it. Nokku only hears about the sync once the server is
written. Run it again whenever access changes.

Every user pins the host key that the last sync saw. When it changed, the
sync stops and writes nothing. If you reinstalled the server, run it again
with `--accept-host-key` to pin the new one.

For scripts, `--json` prints one object with the target, the files written,
and the stale principals files removed. Progress goes to stderr. With
`--dry-run` it is the same object and nothing is written.

`nk target delete` undoes it:

```bash
nk target delete web        # or the address, like nk sync
```

It removes the drop-in, the CA, and the principals files over the same root
ssh, reloads sshd, and only then deletes the target in Nokku. If sshd rejects
its config without the drop-in, everything is put back and the target stays.
Pass `--keep-host` when the server is already gone.

## Uninstall

```bash
nk logout # Removes credentials and config

# Manual uninstall
rm -f ~/.local/bin/nk      # or /usr/local/bin/nk after a --system install
rm -rf ~/.config/nk
```

## Hosting

<img alt="Static Badge" src="https://img.shields.io/badge/OSS%20hosting%20by-cloudsmith-blue?logo=cloudsmith&style=flat-square&link=https%3A%2F%2Fcloudsmith.com"></img>

Package repository hosting is graciously provided by [Cloudsmith](https://cloudsmith.com).
