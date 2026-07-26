# WireGuard API V2

WireGuard-compatible node API for provisioning clients on a dedicated
AmneziaWG 2.0 server. The HTTP API remains compatible with the existing
`wireguard-api` node contract, so the backend can register this as a separate
server without changing its provisioning calls.

This repository is for new AWG2 VPSs. Existing AWG1/legacy VPSs and their
configs are not modified.

## Install on a clean VPS

Use the AWG2-only entry point:

```bash
curl -sSL https://raw.githubusercontent.com/akromjon/wireguard-api-2/main/install2.sh -o install2.sh
chmod +x install2.sh
sudo ./install2.sh
```

The installer:

- installs the AmneziaWG kernel/tools packages for the host OS;
- creates a new `awg0` interface and `/etc/amnezia/amneziawg/params`;
- writes an AWG2 server config with S3, S4, and non-overlapping H ranges;
- installs the API service and sets `AWG_PROFILE=awg2`;
- leaves legacy VPSs outside this repository untouched.

Use a separate VPS and backend server record for this pool. Do not point an
existing AWG1 server record at this node until the node has been tested with
the intended iOS client engine.

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

Old AWG1 configs should stay on the existing AWG1 nodes. A new AWG2 config
requires a client engine that supports AWG2 and the corresponding server
implementation; do not silently rewrite old configs in place.

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

## Build and test

```bash
go test ./...
./installer_test.sh
go build -o wireguard-api-2 .
./build.sh
```

`build.sh` creates release binaries under `bin/`. `service.sh` expects the
published release tag `v2.0.0` by default; override it with
`WIREGUARD_API_RELEASE_TAG` during a canary release.

## Operations

```bash
systemctl status awg-quick@awg0
systemctl status wireguard.service
journalctl -u wireguard.service -f
```

Keep the API token private and restrict access to the API port with the VPS
firewall or a trusted control-plane network.

## Documentation references

- [AmneziaWG 2.0 self-hosted instructions](https://docs.amnezia.org/documentation/instructions/new-amneziawg-selfhosted/)
- [AmneziaWG Go implementation](https://github.com/amnezia-vpn/amneziawg-go)
- [AmneziaWG kernel module](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module)
