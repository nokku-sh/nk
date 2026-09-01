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

The installer prefers your distro's package (deb/rpm/apk) via the Cloudsmith
repository and falls back to the GitHub release binary.

Prefer manual packages? See the [package repository](https://broadcasts.cloudsmith.com/nokku/nk) for apt/dnf/apk install instructions.

Authenticate via your browser and connect:

```bash
nk login          # Authenticate and sync your SSH config
nk ls             # List the targets you can access
ssh user@target   # Connect using standard OpenSSH!
```

> [!NOTE]
> Access is synced just in time: every `nk ls` and every SSH connection refreshes what you can reach, so grants and revocations apply immediately. When the backend is unreachable, `nk` fails fast and works seamlessly from cached data and existing valid certificates.

## Hardware Security (TPM 2.0)

On Linux and Windows, `nk` automatically uses a TPM 2.0 when one is available. Your SSH private key becomes a deterministic primary key that never leaves the TPM; signing happens via an embedded SSH agent (`agent.sock`). Without a TPM, `nk` falls back to a software key transparently. Pass `--require-tpm` to refuse that fallback.

_(Check `nk doctor` to see if a TPM is available and in use.)_

> [!NOTE]
> On most Linux distributions `/dev/tpmrm0` is owned by `root:tss`, so regular users cannot use the TPM by default. Fix: `sudo usermod -aG tss $USER` and log in again (a udev rule granting your user access works too).

### Headless / CI

Use a service-account API key in CI or other headless environments:

```bash
export NK_TOKEN=<KEY_ID>.<SECRET>
nk login
ssh user@target
```

## X.509 certificates (experimental)

`nk` can also issue certificates for API clients, servers, and other workloads:

```bash
nk pki list
nk pki issue api-client --usage client --san dns:api.example.com
```

The command generates a key pair, requests a signed certificate, and saves the certificate, private key, and CA certificate to the output directory.

## Commands

| Command              | Purpose                                    |
| -------------------- | ------------------------------------------ |
| `nk login`           | Authenticate and synchronize local state   |
| `nk refresh`         | Re-authenticate and refresh state          |
| `nk ls` / `nk list`  | List targets and principals                |
| `nk doctor`          | Check API reachability and local SSH setup |
| `nk pki list`       | List active X.509 certificate authorities  |
| `nk pki issue <cn>` | Issue an X.509 certificate                 |
| `nk logout`          | Remove local credentials and cached state  |
| `nk proxy`           | Internal OpenSSH `ProxyCommand` (internal) |

## Configuration

| Flag         | Environment   | Purpose                                                                 |
| ------------ | ------------- | ----------------------------------------------------------------------- |
| `--api`      | `NK_API_URL`  | Backend URL                                                             |
| `--token`    | `NK_TOKEN`    | Service-account API key (`keyID.secret`); skips browser login for CI/CD |
| `--ttl`      | `NK_TTL`      | Requested SSH certificate lifetime                                      |
| `--require-tpm` | `NK_REQUIRE_TPM` | Require a TPM 2.0; refuse the software key fallback                  |
| `--insecure` | `NK_INSECURE` | Disable TLS verification; testing only                                  |

Local state lives under `~/.config/nk/`. Your private key and tokens are credentials. Keep service-account tokens out of source control.

## Uninstall

```bash
nk logout # Removes credentials and config

# Manual uninstall
rm -f /usr/local/bin/nk   # or wherever nk was installed
rm -rf ~/.config/nk
```

## Hosting

<img alt="Static Badge" src="https://img.shields.io/badge/OSS%20hosting%20by-cloudsmith-blue?logo=cloudsmith&style=flat-square&link=https%3A%2F%2Fcloudsmith.com"></img>

Package repository hosting is graciously provided by [Cloudsmith](https://cloudsmith.com).
