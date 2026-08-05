# WireGuard API V2

WireGuard-compatible node API for provisioning clients on an AmneziaWG 2.0
server. The HTTP API remains compatible with the existing
`wireguard-api` node contract, so the backend can register this as a separate
server without changing its provisioning calls.

The installer supports either a clean AWG2 VPS or an isolated AWG2 interface
alongside an existing AWG1/legacy interface. Existing legacy VPN configs,
peers, and listener ports are not rewritten; the existing node API binary is
upgraded in place to generate AWG2 configs.

## Install on a clean or legacy VPS

Use the AWG2-only entry point:

```bash
curl -sSL https://raw.githubusercontent.com/akromjon/wireguard-api-2/main/install2.sh -o install2.sh
chmod +x install2.sh
sudo ./install2.sh
```

The installer:

- installs the AmneziaWG kernel/tools packages for the host OS;
- inventories existing AWG configs, live interfaces, VPN UDP ports, and node
  API TCP ports before making changes;
- creates `awg0` on a clean host or proposes the next free interface such as
  `awg1` when a legacy interface is present;
- assigns a separate params file, tunnel network, generated-client directory,
  and VPN UDP port to a co-located AWG2 interface;
- writes an AWG2 server config with S3, S4, and non-overlapping H ranges;
- installs the API service on a clean host or upgrades the existing binary on
  its current TCP port, preserving the API token and backend endpoint;
- displays the complete installation layout and requires the operator to type
  `INSTALL-AWG2` before changing the host.

The existing legacy UDP port is reported but reserved. A co-located AWG2
interface must use a different UDP port; changing only the port does not make a
legacy wire profile compatible with AWG2. A lower unused port, including UDP
443 when available, may improve reachability on restrictive networks.

On a co-located upgrade, the existing backend server record, public IP, TCP
port, and API token remain unchanged. After the service restart, provisioning
calls on that endpoint create AWG2 configs for `awg1`. The legacy `awg0`
interface remains up temporarily so previously issued configs continue to pass
traffic during rotation.

`install.sh` is also AWG2-only for convenience. `install2.sh` is the preferred
stable entry point and accepts `WIREGUARD_API_REPOSITORY` and
`WIREGUARD_API_REF` for canary testing.

## AWG2 configuration

The installer asks for the AmneziaWG parameters and writes the same values to
the server and generated client configs:

- `Jc`, `Jmin`, `Jmax`, `S1`, and `S2` retain the existing AmneziaWG behavior.
- `S3` and `S4` are AWG2 padding values. The documented ranges are `0–64`
  bytes for S3 and `0–32` bytes for S4. They are always persisted, including
  `0`, which disables that padding dimension.
- `H1`–`H4` accept a single value or an inclusive `min-max` range. The
  installer rejects invalid, out-of-bounds, and overlapping ranges.
- `I1`–`I5` are optional custom signature packet definitions. Empty values are
  omitted from configs rather than emitted as empty directives.

Every generated client config contains the comment:

```ini
# CHOP-AWG-PROFILE: awg2
```

It is metadata only and does not change the WireGuard config grammar. The
AWG2 directives are the actual engine-selection signal for a client that
supports them. Do not add an unknown `Protocol = awg2` directive.

The installer defaults to a UDP port at or below `9999`, because the Amnezia
documentation notes that some networks block higher UDP ports. Port `443`
can be selected when it is available, but the listener port and the optional
`USE_UDP_443_ENDPOINT` client-endpoint mode remain separate settings.

## Compatibility and profile selection

The node API response is unchanged:

```json
{
  "name": "client1",
  "ipv4": "10.66.0.2",
  "ipv6": "fd42:42:42::2",
  "config": "[Interface]..."
}
```

AWG2 is selected explicitly by `AWG_PROFILE=awg2`, not inferred from one
parameter such as `S3` or `S4`. Missing AWG2 metadata is therefore a startup
error on an AmneziaWG v2 node. `AWG_PROFILE=legacy` is retained only for
controlled compatibility tests; it is not the production installer default.

The installer does not perform client-version gating. It assumes AWG2 config
compatibility has already been validated for the supported client population.
Previously issued legacy configs remain usable through `awg0` while users are
rotated to newly generated AWG2 configs.

The node installer does not rewrite configuration assignments already stored by
the backend. Before retiring `awg0`, run a separate controlled backend rotation
that generates or imports AWG2 configurations and replaces each user's stored
legacy assignment. No application-version gating is needed because AWG2 config
compatibility with the supported devices has already been validated.

## API

All endpoints require the API token in the `key` header:

```text
key: your-api-token
```

Available routes:

- `GET /api/users` — list clients
- `POST /api/users/add` — add one client
- `POST /api/users/add-bulk` — add up to 500 clients
- `POST /api/users/delete` — delete one client
- `POST /api/users/delete-all` — delete all clients
- `GET /api/health` — lightweight running-state check
- `GET /api/status` — detailed interface status
- `POST /api/start`, `/api/stop`, `/api/restart` — service controls

The request and response shapes are intentionally the same as v1. See
[`openapi.yml`](./openapi.yml) for the complete contract.

### Co-located API service

There is still only one node API process and one public management port:

| Stage | VPN interface | API service | API port | API token |
| --- | --- | --- | --- | --- |
| Before upgrade | `awg0` legacy | `wireguard.service` | TCP `8080` | Existing token |
| After upgrade | `awg1` AWG2 | `wireguard.service` | TCP `8080` | Same token |

The upgraded service loads the AWG2 config, params, and generated-client path.
It verifies that the existing token now reaches `awg1` on the existing TCP
port. If verification fails, the installer restores the previous binary,
environment, and systemd unit. It does not create a duplicate backend record.

## Build and test

```bash
go test ./...
./installer_test.sh
go build -o wireguard-api-2 .
./build.sh
```

`build.sh` creates release binaries under `bin/`. By default, `service.sh`
downloads the matching asset from GitHub's latest published release, so the
installer does not need a hard-coded version bump. Set
`WIREGUARD_API_RELEASE_TAG` only when a canary or rollback must be pinned to a
specific release, or set `WIREGUARD_API_BINARY` to install a local binary.

## Operations

```bash
systemctl status awg-quick@awg1
systemctl status wireguard.service
journalctl -u wireguard.service -f
```

After the upgrade, `wireguard.service` manages `awg1`. The legacy `awg0`
interface stays running only as the temporary data-plane fallback for old
configs until the rotation is complete.

Keep the API token private and restrict access to the API port with the VPS
firewall or a trusted control-plane network.

## Documentation references

- [AmneziaWG 2.0 self-hosted instructions](https://docs.amnezia.org/documentation/instructions/new-amneziawg-selfhosted/)
- [AmneziaWG Go implementation](https://github.com/amnezia-vpn/amneziawg-go)
- [AmneziaWG kernel module](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module)
