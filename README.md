# HostWatch Agent

This repository contains the standalone Python agent used by HostWatch nodes.

The Home Assistant custom integration now lives in a separate repository:

- Integration: [github.com/Dag0d/HostWatch](https://github.com/Dag0d/HostWatch)

## What This Repository Contains

- [`agent/hostwatch_agent.py`](agent/hostwatch_agent.py): the HostWatch node agent
- [`agent/install.sh`](agent/install.sh): local and remote installer
- [`agent/README.md`](agent/README.md): installation and operational details
- [`docs/agent_updates.md`](docs/agent_updates.md): signed release process and update security model
- [`scripts/build_agent_release.py`](scripts/build_agent_release.py): build helper for signed release artifacts

## Purpose

The agent runs on Linux hosts and:

- collects local system state
- sends heartbeats and metrics to Home Assistant
- polls Home Assistant for allowlisted maintenance actions
- installs signed agent updates from this repository's GitHub Releases

It is intentionally not a remote shell and does not accept arbitrary commands.

## Installation

Quick start on a target host:

```sh
cd agent
sudo ./install.sh
```

For full installation, remote install, and update examples, see [`agent/README.md`](agent/README.md).

## Signed Releases

This repository is the release source for signed agent updates.

The Home Assistant integration queries these releases and exposes them through a standard Home Assistant `update` entity. The agent then downloads and verifies:

- `hostwatch-agent-<version>.tar.gz`
- `hostwatch-agent-manifest-<version>.json`
- `hostwatch-agent-manifest-<version>.sig`

More detail is in [`docs/agent_updates.md`](docs/agent_updates.md).

## Related Repository

For the Home Assistant integration, HACS setup, and overall integration docs, use:

- [github.com/Dag0d/HostWatch](https://github.com/Dag0d/HostWatch)
