# HostWatch Python Agent

This repository contains the HostWatch node agent only.

The Home Assistant integration lives separately at:

- [github.com/Dag0d/HostWatch](https://github.com/Dag0d/HostWatch)

The agent requires only:

- `python3`
- `openssl`
- SSDP works without extra packages

## Test Run

```sh
HOSTWATCH_CONFIG_PATH=$(pwd)/agent.json python3 hostwatch_agent.py pair
HOSTWATCH_CONFIG_PATH=$(pwd)/agent.json python3 hostwatch_agent.py run
```

## Installation

Local installation on the target host:

```sh
sudo ./install.sh
sudo ./install.sh --update
sudo ./install.sh --remove
```

The installer:

- copies the agent to `/opt/hostwatch`
- installs `hostwatch_agent.py`, `install.sh`, and `release_signing_public.pem`
- writes the configuration to `/etc/hostwatch/agent.json`
- writes cache and state data to `/var/lib/hostwatch/agent.state.json`
- creates `/usr/local/bin/hostwatch-agent`
- installs and starts `hostwatch-agent.service`
- runs interactive configuration and pairing

After installation, the agent starts automatically after every boot.

An update with `--update` stops a running `hostwatch-agent.service`, replaces the agent, wrapper, and systemd unit, keeps `/etc/hostwatch/agent.json` and `/var/lib/hostwatch/agent.state.json` unchanged, and starts the service again afterwards. It does not trigger a new pairing flow.

Removal with `--remove` stops and disables `hostwatch-agent.service` and deletes the service, wrapper, installation directory, config, and state. The node must then be installed and paired again from scratch.

Logs:

```sh
journalctl -u hostwatch-agent.service -f
```

## Remote Installation

From macOS or another Linux system to a Linux/systemd target host:

```sh
./install.sh --remote admin@example-host --ssh-key ~/.ssh/id_ed25519
./install.sh --remote admin@example-host --ssh-key ~/.ssh/id_ed25519 --update
./install.sh --remote admin@example-host --ssh-key ~/.ssh/id_ed25519 --remove
```

With a custom SSH port:

```sh
./install.sh --remote admin@example-host --ssh-key ~/.ssh/id_ed25519 --ssh-port 2222
./install.sh --remote admin@example-host:2222 --ssh-key ~/.ssh/id_ed25519
```

The local machine needs only `ssh` and `scp`. The target host needs `python3`, `openssl`, and `systemd`.

## Useful Options

```sh
./install.sh --help
sudo ./install.sh --no-pair
sudo ./install.sh --no-config
sudo ./install.sh --no-enable
```

`--no-pair` is useful when you want to reuse an existing `/etc/hostwatch/agent.json`.

## Home Assistant Entity IDs

New entities use the suggested entity ID pattern `hostwatch_<node_name>_<entity>`. `<node_name>` is the Home Assistant slugified node name, for example `example-node` becomes `example_node`.

Sensors:

```yaml
sensor.hostwatch_<node_name>_agent_version
sensor.hostwatch_<node_name>_cpu_usage_percent
sensor.hostwatch_<node_name>_cpu_load_1m
sensor.hostwatch_<node_name>_cpu_load_5m
sensor.hostwatch_<node_name>_cpu_load_15m
sensor.hostwatch_<node_name>_cpu_temperature_c
sensor.hostwatch_<node_name>_memory_used_percent
sensor.hostwatch_<node_name>_memory_total_bytes
sensor.hostwatch_<node_name>_memory_used_bytes
sensor.hostwatch_<node_name>_memory_available_bytes
sensor.hostwatch_<node_name>_fs_root_used_percent
sensor.hostwatch_<node_name>_fs_root_total_bytes
sensor.hostwatch_<node_name>_fs_root_used_bytes
sensor.hostwatch_<node_name>_fs_root_available_bytes
sensor.hostwatch_<node_name>_uptime_seconds
sensor.hostwatch_<node_name>_apt_upgradable_count
sensor.hostwatch_<node_name>_apt_last_checked
sensor.hostwatch_<node_name>_maintenance_mode
sensor.hostwatch_<node_name>_ip_address_<interface>
```

Binary sensors:

```yaml
binary_sensor.hostwatch_<node_name>_online
binary_sensor.hostwatch_<node_name>_apt_updates_available
binary_sensor.hostwatch_<node_name>_bootloader_update_available
```

Updates:

```yaml
update.hostwatch_<node_name>_agent
```

Buttons:

```yaml
button.hostwatch_<node_name>_maintenance_mode
```

Not created as entities:

```text
refresh_apt_check
apt_upgrade
refresh_bootloader_check
bootloader_upgrade
reboot
shutdown
```

These entries exist only as commands inside the maintenance page. Agent software updates use the dedicated Home Assistant `update` entity instead.

Notes:

- `sensor.hostwatch_<node_name>_ip_address_<interface>` is created once per reported network interface, for example `sensor.hostwatch_example_node_ip_address_eth0`.
- `binary_sensor.hostwatch_<node_name>_bootloader_update_available` is created only for Raspberry Pi nodes when bootloader data is present.
- Existing entities are not renamed automatically by Home Assistant. The naming scheme applies to newly created entities or after manually removing and recreating old entity IDs.

## Recorder Exclude Example

If Home Assistant records everything by default, this exclude list is a good starting point. It removes static metadata, absolute capacity values, IP addresses, maintenance status, and the maintenance button from the recorder. Percentages, CPU load, temperature, APT counts, and update binary sensors remain recorded.

```yaml
recorder:
  exclude:
    entity_globs:
      - sensor.hostwatch_*_agent_version
      - sensor.hostwatch_*_memory_total_bytes
      - sensor.hostwatch_*_memory_used_bytes
      - sensor.hostwatch_*_memory_available_bytes
      - sensor.hostwatch_*_fs_root_total_bytes
      - sensor.hostwatch_*_fs_root_used_bytes
      - sensor.hostwatch_*_fs_root_available_bytes
      - sensor.hostwatch_*_uptime_seconds
      - sensor.hostwatch_*_apt_last_checked
      - sensor.hostwatch_*_maintenance_mode
      - sensor.hostwatch_*_ip_address_*
      - button.hostwatch_*_maintenance_mode
```
