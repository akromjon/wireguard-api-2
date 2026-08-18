# AWG3 conversion runbook

One node at a time. Never batch.

**No user may be disconnected, and no user may be left unable to connect.**
Everything below exists to hold that line.

There are two paths. Pick by whether the node can reach zero live peers:

- **Path A — premium nodes.** Nearly idle, so they hit zero live peers on their
  own. AWG3 takes 443 *before* the row is cut over, so allocations never point
  at a non-443 port. Use this for every premium node.
- **Path B — free nodes 313, 314, 321.** ~370 users each; they never reach zero
  while their row is serving, so the row must be retired first. That opens a
  real `:8443` window. Use this only for the three free nodes, and only at the
  free tier's traffic trough.

## Before you touch anything

Confirm the node is not on the macOS floor. **298 Stockholm and 304 Milan stay
AWG2 permanently** — they are the only servers a macOS client can be offered,
because `client_supports_awg3` denies macOS unconditionally. Converting them
strands every macOS user with a 404 and no Fastest fallback.

## Counting live peers

`latest-handshakes` is cumulative — it never returns to zero, so it is the wrong
gate. A peer is live if it handshook within the last 3 minutes (WireGuard rekeys
every ~2):

```bash
if ! dump=$(sudo awg show awg1 dump 2>&1); then
    printf 'GATE FAILED — could not read awg1: %s\nDo NOT take 443.\n' "$dump"
else
    printf '%s\n' "$dump" | awk -v n="$(date +%s)" 'NR>1 && $5>0 && n-$5<180 {c++} END {print "live peers: " c+0}'
fi
```

This prints one of two things. `GATE FAILED — could not read <iface>: ...` means
the command did not run — do not proceed, investigate the error. `live peers: N`
means the command ran and counted `N` live peers; `live peers: 0` is the only
string that confirms zero. Any other output — a bare `0`, no output at all, a
shell error not wrapped in `GATE FAILED` — means the command did not run as
intended. Do not treat that as a zero. Stop and investigate instead.

## Shared steps 1-3 (both paths, nobody affected)

### 1. Flag the row FIRST

The node's single API is repointed to AWG3 by the install. If the backend row is
not flagged before that happens, the node hands AWG3 configs to clients that
cannot use them.

```bash
php artisan tinker --execute='App\Models\Server::find(<id>)->update(["is_support_awg_third" => true]);'
```

### 2. Preflight (read-only, changes nothing)

```bash
scp awg2-preflight.sh awg3-sidecar.sh amneziawg-install.sh <node>:/tmp/
ssh <node> 'bash /tmp/awg2-preflight.sh --awg3 --port 8443 --iface awg3'
```

A `loaded amneziawg module is 1.x` failure means this node needs `apt upgrade`
**and a reboot** before it can be converted. The reboot drops its live users —
schedule it, do not improvise it.

### 3. Install the sidecar, then prove it

```bash
ssh <node> 'bash /tmp/awg3-sidecar.sh'          # dry run, prints the plan
ssh <node> 'bash /tmp/awg3-sidecar.sh --apply'
```

The incumbent interface keeps serving on 443 for the whole DKMS build. Read the
SUMMARY line: `ok=yes`, and `awg2_peers=<N>` is the parity target for the
cutover. Any failed check — stop, restore from the printed backup path.

If the node has multiple existing WireGuard interfaces and the script refuses
with a message about `--incumbent`, re-run specifying which interface to keep
alongside AWG3:

```bash
ssh <node> 'bash /tmp/awg3-sidecar.sh --incumbent awg1'          # dry run
ssh <node> 'bash /tmp/awg3-sidecar.sh --incumbent awg1 --apply'
```

This is expected when a node has been converted before or serves multiple
profiles.

Then connect a real client to `:8443` and confirm, on the node:

```bash
if ! dump=$(sudo awg show awg3 dump 2>&1); then
    printf 'GATE FAILED — could not read awg3: %s\nDo NOT cut over.\n' "$dump"
else
    printf '%s\n' "$dump" | awk 'NR>1 && $5>0 {c++} END {print "peers with a completed handshake: " c+0}'
fi
```

This gate asks a different question than the live-peer gate above: has *any*
client completed a handshake on the new interface at all, ever — not whether
one is live right now. There is no 180-second window here.

Must print `peers with a completed handshake: N` with `N` greater than zero. A
`GATE FAILED` line means the command did not run — investigate before treating
this as proof of anything, and do not cut over. An off-box UDP probe is **not**
proof either: `tcpdump` captures at the device layer, so probe packets appear
even when the listener never receives them.

## Path A (premium) — take 443, then cut over

### A4. Wait for a natural zero

Poll until the incumbent reports **0** live peers. Nothing is retired, so this
is simply a quiet moment on a lightly-loaded node. Use the live-peer gate command
from above:

```bash
if ! dump=$(sudo awg show awg1 dump 2>&1); then
    printf 'GATE FAILED — could not read awg1: %s\nDo NOT take 443.\n' "$dump"
else
    printf '%s\n' "$dump" | awk -v n="$(date +%s)" 'NR>1 && $5>0 && n-$5<180 {c++} END {print "live peers: " c+0}'
fi
```

Repeat until you see "live peers: 0" with no error prefix.

### A5. Take 443

Have the A6 command typed and ready before running this.

```bash
ssh <node> 'bash -s' < awg2-port443.sh -- --iface awg3 --old-iface awg1 --apply
```

At zero live peers this drops nobody. It rewrites `SERVER_PORT` in the params
file and `AWG_PORT` in the API env, so every config issued from now carries
`:443`. It rolls itself back on any failed check.

### A6. Cut over the row — immediately

```bash
php artisan servers:awg3-cutover --server-id=<id> --configs=<N> --apply
```

Run this straight after A5. Between the two, the active row is the AWG2 one
while its interface is already down, so a user allocated in that gap gets a
config for a dead interface. Seconds, one city — but do not leave it open.

The pool is seeded while the node is already on 443, so its configs are correct
with no Endpoint rewrite needed.

## Path B (free) — cut over, drain, then take 443

### B4. Cut over at the traffic trough

```bash
php artisan servers:awg3-cutover --server-id=<id> --configs=<N>          # dry run
php artisan servers:awg3-cutover --server-id=<id> --configs=<N> --apply
```

From here new allocations go to AWG3 on `:8443`. **This is the one window in the
rollout where users are affected:** networks that pass only UDP 443 cannot
connect to this city until B6. Measured 2026-08-09 — users who could not connect
had 588 past successes on :443 and 9 on :8081, same node and IP. Keep it short.

### B5. Drain

Live users keep their AWG2 configs until they reconnect; every reconnect
resolves the location group to the AWG3 clone and releases the old config back
to the pool. Poll live peers on the incumbent until they read **0**. Use the
live-peer gate command:

```bash
if ! dump=$(sudo awg show awg1 dump 2>&1); then
    printf 'GATE FAILED — could not read awg1: %s\nDo NOT take 443.\n' "$dump"
else
    printf '%s\n' "$dump" | awk -v n="$(date +%s)" 'NR>1 && $5>0 && n-$5<180 {c++} END {print "live peers: " c+0}'
fi
```

Repeat until you see "live peers: 0" with no error prefix.

### B6. Take 443, then fix the stored endpoints

First, take port 443 on the node:

```bash
ssh <node> 'bash -s' < awg2-port443.sh -- --iface awg3 --old-iface awg1 --apply
```

The AWG3 pool was seeded while the node was on `:8443`, so its stored configs
still say `:8443`. Rewrite just the `Endpoint` line on that row's configs — the
peer keys are unchanged, so the pool does **not** need regenerating.

Dry-run count:

```bash
php artisan tinker --execute='
$s = App\Models\Server::find(<clone-id>);
$n = 0;
foreach ($s->configs()->cursor() as $c) {
    if (preg_match("/^Endpoint\s*=\s*\S+:8443\s*$/m", $c->config)) { $n++; }
}
echo "will rewrite {$n} of {$s->configs()->count()} configs from :8443 to :443\n";
'
```

Then apply the rewrite:

```bash
php artisan tinker --execute='
$s = App\Models\Server::find(<clone-id>);
$n = 0;
foreach ($s->configs()->cursor() as $c) {
    $new = preg_replace("/^(Endpoint\s*=\s*\S+):8443(\s*)$/m", "$1:443$2", $c->config, -1, $count);
    if ($count > 0) {
        $c->update(["config" => $new]);
        $n += $count;
    }
}
echo "rewrote {$n} config(s) from :8443 to :443\n";
'
```

## Both paths: after the cutover

**Never run "Sync Server" or a pool top-up on either row.** The node API serves
AWG3, so either would write AWG3 configs into the retired AWG2 row and delete
the config rows live users still hold.

Soft-delete the retired row once its interface is gone.

## Rollback

Before AWG3 takes 443 — free on both paths:

```bash
ssh <node> 'systemctl stop awg-quick@awg3; awg-quick up awg1'
```

`awg2-port443.sh` rolls itself back automatically on a failed check, restoring
the config, params and API env and re-enabling the old interface.

After the row cutover:

```bash
php artisan tinker --execute='App\Models\Server::find(<old-id>)->update(["status" => "active"]); App\Models\Server::find(<clone-id>)->update(["status" => "inactive"]);'
```

Live users were never moved, so there is nothing to undo on the node itself.
Once the old interface is torn down and its configs are gone, that node is
committed.
