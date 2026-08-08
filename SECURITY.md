# Security Policy

## Supported Versions

Only the latest release of `nk` is supported for security fixes. Older
releases are not patched; if you are affected by a vulnerability, upgrade to
the newest tagged release.

## Reporting a Vulnerability

Please **do not** open a public issue for a suspected security vulnerability.
Use GitHub's private vulnerability reporting instead:

1. Open the repository's **Security** tab.
2. Select **Report a vulnerability**.
3. Provide as much of the following as you can:

   - Affected `nk` version and platform/distribution
   - A description of the issue and its security impact
   - Steps to reproduce, or a minimal patch/poc
   - Any supporting logs (redact secrets)

Reports are handled confidentially. We will acknowledge receipt, and if you
would like to be credited in the release advisory or changelog, let us know —
this is optional but appreciated.

### Response timeline

- **Acknowledge** the report: within 48 hours
- **Triage** and classify severity: within 5 business days
- **Fix / mitigation / response**: we aim to provide a fix or clear guidance
  within 30 days, depending on the complexity and impact.

## Scope

The following are in scope for security reports:

- The `nk` CLI binary — the browser-based login flow, service-account token
  handling, SSH certificate request/signing, the OpenSSH `ProxyCommand`
  implementation, and X.509 certificate issuance.
- Local state and configuration it writes under `~/.config/nk/`:
  - `config.json`, `cache.json`, `ssh_config`, `known_hosts`
  - `nokku` / `nokku.pub` (local key and public key)
  - `certs/` and any issued certificate output

### Out of scope

- The Nokku **backend** and web application (separate repositories).
- The SSH protocol itself and vulnerabilities in OpenSSH / `sshd`.
- OS/distribution and package-manager issues.
- The infrastructure hosting the Nokku backend.

## Security Notes / Threat Model

`nk` is a workstation CLI that holds authentication tokens, manages the
user's SSH key, and requests signed SSH and X.509 certificates from the
backend.

- Local credentials and cache live under `~/.config/nk/`. The private key
  (`nokku`) and authentication tokens are credentials — protect this
  directory and keep service-account tokens out of source control.
- When the backend is unavailable, `nk` can use cached target data and an
  existing certificate, but cannot refresh access or issue a new certificate
  while offline.
- Releases are built via GoReleaser and signed/checksummed — verify downloads
  against the published checksums and signatures.
