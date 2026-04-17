# Signed Agent Updates

HostWatch agent updates are distributed through GitHub Releases and exposed in Home Assistant through the standard `update` entity.

This repository is the dedicated HostWatch agent release source. The Home Assistant integration repository lives separately at [github.com/Dag0d/HostWatch](https://github.com/Dag0d/HostWatch).

## Security Model

- Home Assistant does not upload code directly to a node.
- Home Assistant only queues the allowlisted `agent_update` command with a target version.
- The node downloads release assets itself from the official GitHub release.
- The node verifies a detached signature over the release manifest with the built-in public key in `agent/release_signing_public.pem`.
- The manifest contains the tarball URL and SHA256. The node verifies the tarball against that signed SHA256 before installing anything.

This means a compromised Home Assistant instance cannot turn the agent update path into arbitrary remote code execution unless it also has the release signing key.

## Required GitHub Secret

Create this repository secret under:

`GitHub repository -> Settings -> Secrets and variables -> Actions -> New repository secret`

Secret name:

```text
HOSTWATCH_RELEASE_SIGNING_KEY_PEM
```

Secret value:

- the complete PEM-encoded private key
- including the `-----BEGIN PRIVATE KEY-----` and `-----END PRIVATE KEY-----` lines

Example generation commands:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out hostwatch-release-signing-private.pem
openssl pkey -in hostwatch-release-signing-private.pem -pubout -out agent/release_signing_public.pem
```

Commit only the public key. Never commit the private key.

## Release Flow

1. Update the agent version in `agent/hostwatch_agent.py`.
2. Create and publish a GitHub Release with the matching tag, for example `2026.4.3`.
3. GitHub Actions builds:
   - `hostwatch-agent-<version>.tar.gz`
   - `hostwatch-agent-manifest-<version>.json`
   - `hostwatch-agent-manifest-<version>.sig`
4. The workflow uploads those three assets to the release.
5. The separate Home Assistant integration repository checks the latest GitHub release here and exposes the agent update through the built-in update entity.

## Installed Files on the Node

The signed tarball currently contains only the strict allowlist below:

- `hostwatch_agent.py`
- `install.sh`
- `release_signing_public.pem`

The agent installs only those files into its current install directory and then restarts its own systemd service.

## Related Repository

The Home Assistant integration that consumes these signed agent releases lives here:

- [github.com/Dag0d/HostWatch](https://github.com/Dag0d/HostWatch)
