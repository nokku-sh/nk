# Security

This file has two parts. The first is for reporting a vulnerability. The second is for people who use `nk` and want to know how it protects them.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use GitHub's private reporting instead:

1. Open the repository's **Security** tab.
2. Select **Report a vulnerability**.
3. Tell us as much of this as you can:
   - The `nk` version and your platform or distribution
   - What the issue is and what an attacker gains
   - Steps to reproduce, or a minimal proof of concept
   - Logs that help, with secrets removed

Reports are handled confidentially. If you would like credit in the advisory or the changelog, say so.

What to expect:

- **Acknowledgement** within 48 hours
- **Triage** and a severity within 5 business days
- **A fix or clear guidance** within 30 days, depending on complexity and impact

### Supported versions

Only the latest release gets security fixes. Older releases are not patched, so upgrade to the newest release.

### In scope

- The `nk` binary: the browser sign-in, service account tokens, requesting SSH certificates, the OpenSSH `ProxyCommand` and issuing X.509 certificates
- The local state it writes under `~/.config/nk/`:
  - `config.json` and `cache.json`
  - `ssh-signer.json`, the SSH signing identity, and `signer.json`, the DPoP signing identity
  - `agent.sock`, the local agent socket `ssh` uses for signing
  - `ssh_config`, `known_hosts` and `nokku.pub`
  - `certs/` and any certificate it issued

### Out of scope

- The Nokku core and web app, which have their own [policy](https://github.com/nokku-sh/nokku/blob/main/SECURITY.md)
- The SSH protocol itself, and vulnerabilities in OpenSSH or `sshd`
- Operating system and package manager issues
- The infrastructure that hosts the Nokku core

## Using nk securely

`nk` runs on your workstation. It holds your sign-in tokens, manages your SSH key and asks the core for signed SSH and X.509 certificates.

### How nk protects your key

- **With a TPM 2.0**, on Linux and Windows, your SSH private key is a deterministic primary key that never leaves the TPM. `nk` uses one automatically when it finds one.
- **Signing happens in a small background agent.** `nk` starts it on the first SSH connection and stops it after 30 idle minutes. `ssh` reads the key only through the agent socket, never directly.
- **Without a TPM**, `nk` falls back to a software ECDSA P-256 key, wrapped with a key derived from the machine fingerprint. The state file is useless on another machine. On the machine itself it is only as safe as its file permissions.
- **`--require-tpm` refuses the fallback.** Use it where a TPM is expected.
- **On macOS**, `NK_SECURE_ENCLAVE=1` keeps new keys in the Secure Enclave, as an opaque blob only that Mac can use. This is experimental.

`nk doctor` shows which of these is in use.

### Your local state

- Everything under `~/.config/nk/` is a credential: the signer state, the SSH certificates and the sign-in tokens. Protect the directory.
- `nk logout` removes it and stops the agent.

### Service account tokens

- Sessions from `nk login` are bound to your machine key. A service account token is not, it is a plain bearer token. Treat it like a password.
- Pass it as `NK_TOKEN`. It is never accepted as a flag.
- Keep it out of source control, and use your CI system's secret store.

### TLS

`--insecure` turns off TLS verification. It is for testing only, and `nk` prints a warning whenever it is on.

An `http://` API URL is refused without it, unless it points at this machine.

### Releases

- Releases are built with GoReleaser. Each one publishes `nk_checksums.txt`, a cosign signature bundle for it (`nk_checksums.txt.sigstore.json`) and a CycloneDX SBOM per binary.
- `install.sh` checks the SHA-256 of the binary it downloads against the checksum manifest. It verifies the manifest with cosign when cosign is available, and stops on a mismatch.
- You can check the manifest by hand with `cosign verify-blob`, against the attached bundle and the GitHub Actions OIDC issuer.
- The deb, rpm and apk packages come from the Cloudsmith repository. The package manager checks them against the repository key.

## What to know about the design

**Offline.** When the core is unavailable, `nk` uses cached target data and a certificate you still hold. It cannot refresh access or get a new certificate until the core is back.

**Servers enforce access, not `nk`.** `nk` shows what you can reach, but the server decides. A revoke applies on the server, whatever the local cache says.
