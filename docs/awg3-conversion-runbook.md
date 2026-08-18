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

**The row is NOT flagged before the cutover.** `servers:awg3-cutover` sets
`is_support_awg_third` on the clone, at cutover, and never on the row that is
still serving. Flagging early would hide the city from every old-iOS and macOS
client for the whole (unbounded) wait for a zero-live-peer moment — which
breaks "nobody may be left unable to connect" just as surely as a dropped
tunnel. The hazard that early flag was guarding — something writing AWG3
configs into the still-AWG2 row — is closed instead by pausing the crons
(below) and by the Filament actions now being disabled on non-active rows.

## Naming the incumbent interface, and getting a shell on the node

**Do not assume the incumbent interface is `awg1`.** 19 nodes serve `awg1`;
**325, 321 and 322 serve `awg0`.** Following this runbook with the wrong name
gives you a GATE FAILED you cannot clear, an `--old-iface` that no-ops so the
real interface keeps 443, an `awg3` that then cannot bind it, and a rollback
aimed at a systemd unit that does not exist.

So the first thing you do, **before installing anything**, is find out and pin
it. From your workstation:

```bash
ssh <node> 'ip -br link show | grep -oE "^(awg|wg)[0-9]+"'
```

Exactly one name should come back. If more than one does, this node already has
a second interface — stop and work out which one is serving before going
further; the sidecar will also refuse and ask for `--incumbent`.

Now export it **in your workstation shell**, because the commands that run the
node scripts and the artisan commands are typed there:

```bash
export OLD_IFACE=awg1        # or awg0 — use what the command above printed
export NEW_IFACE=awg3
echo "incumbent=$OLD_IFACE new=$NEW_IFACE"
```

Several checks below are run *on* the node instead. Open an interactive shell
for those and export the same two names there:

```bash
ssh <node>          # root@<ip> on most nodes, ubuntu@<ip> on ~10 of them
export OLD_IFACE=awg1        # same value you pinned above
export NEW_IFACE=awg3
```

Each code block below says which shell it belongs to. The variables do not
survive an ssh session, so re-export them in any new one.

## Counting live peers

`latest-handshakes` is cumulative — it never returns to zero, so it is the wrong
gate. A peer is live if it handshook within the last 3 minutes (WireGuard rekeys
every ~2). **On the node:**

```bash
if ! dump=$(sudo awg show "$OLD_IFACE" dump 2>&1); then
    printf 'GATE FAILED — could not read %s: %s\nDo NOT take 443.\n' "$OLD_IFACE" "$dump"
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

180 seconds is also the window `awg2-port443.sh` uses for its own refusal, so
the two sides of this decision agree.

## Pause the crons

**Do this on the backend box, before the sidecar install, on every node and on
both paths.** Three scheduled commands will otherwise act on this node's rows
while the conversion is half-done. The first two do real, silent damage; the
third fails safe, but can still take a row out of service mid-conversion, so
pause it too.

`configs:cleanup-stale` runs **every ten minutes**. It skips *inactive* and
soft-deleted servers only — so on Path A, where the old row stays active for the
whole sidecar→cutover wait, it runs against it. When it reclaims a stale config
it calls `createReplacementConfig`, which asks the node API for a fresh config —
and that API now serves AWG3 with `Endpoint …:8443`. It then writes that AWG3
config into the AWG2 row. Nothing downstream notices.

`servers:connect-check` runs **every minute** and sets `status='inactive'` on
servers it judges unreachable. On Path B this will fire on the fresh clone: B4
deliberately opens a `:8443` window that restricted-network users cannot connect
through, and B5's drain takes hours. Its real thresholds, from
`CheckServerConnectRate`: a free-tier server is scored once it has 100 sessions
within 6 hours *and* 30 within 30 minutes; it is flagged below 40% of the free
tier's own median; two consecutive strikes disable it, up to 3 servers per run.
The config-based veto only holds a disable back when at least 20 of the row's
`in_use`+`connected` configs are at least 50% `connected` — a fresh clone will
not be. If it fires while the old row is already inactive, that city is offline
for everyone.

`servers:health-check` runs **every five minutes**, against every `active`
server. It calls the node's own API health endpoint, retrying up to 5 times
within the run (10s timeout each); if none of the five ever comes back
`running: true`, it sets `status='inactive'` and sends a Telegram alert. On
Path A the old row is `active` for the whole sidecar→cutover wait, so it's in
scope — and the sidecar restarts `wireguard.service` during install, settling
for 60s afterward specifically because, in its own words, "a bad
WG_PARAMS_FILE restart-loops the API." If that happens, this check can flip
the still-serving row to inactive mid-install. **Unlike the other two, this
one fails safe**: it only disables a row when the node API genuinely stops
answering, it tells you immediately via Telegram, and undoing it is the same
one-line reactivate as B7 — no stray configs written, no city silently taken
offline by a miscalibrated heuristic.

Pause all three by taking the scheduler's own overlap mutex. This needs no code
change and no crontab edit: `schedule:run` skips any event whose mutex is
already held. The mutex carries a TTL, so a pause you forget about heals itself.
**On the backend box:**

```bash
php artisan tinker --execute='
$name = "configs:cleanup-stale";
$hours = 12;
$e = collect(app(Illuminate\Console\Scheduling\Schedule::class)->events())
    ->first(fn ($ev) => str_contains((string) $ev->command, $name));
if ($e === null) {
    echo "NOT FOUND: {$name}\n";
} else {
    $e->expiresAt = $hours * 60;
    echo $name, " paused: ", var_export($e->mutex->create($e), true), " (for {$hours}h)\n";
}
'
```

Run it again with `$name = "servers:connect-check"`, then a third time with
`$name = "servers:health-check"`, to pause the other two.

`paused: true` means you now hold the mutex. `paused: false` means that command
is running right now and already holds it — wait a few seconds and repeat, do
not carry on assuming it is paused.

Confirm, without side effects:

```bash
php artisan tinker --execute='
foreach (["configs:cleanup-stale", "servers:connect-check", "servers:health-check"] as $name) {
    $e = collect(app(Illuminate\Console\Scheduling\Schedule::class)->events())
        ->first(fn ($ev) => str_contains((string) $ev->command, $name));
    echo $name, " paused: ", var_export($e->mutex->exists($e), true), "\n";
}
'
```

All three must print `true`. Use `exists()` for this check and not
`shouldSkipDueToOverlapping()` — the latter acquires the mutex as a side effect
and would hold it for only the default few minutes.

12 hours covers a Path A wait and a Path B drain. If the conversion runs longer,
re-run the pause command before the TTL expires.

**All three are re-enabled in "After the cutover" below. Do not skip that.**

## Shared steps 1-3 (both paths, nobody affected)

### 1. Preflight (read-only, changes nothing)

From your workstation:

```bash
scp awg2-preflight.sh awg3-sidecar.sh amneziawg-install.sh <node>:/tmp/
ssh <node> 'bash /tmp/awg2-preflight.sh --awg3 --port 8443 --iface awg3'
```

A `loaded amneziawg module is 1.x` failure means this node needs `apt upgrade`
**and a reboot** before it can be converted. The reboot drops its live users —
schedule it, do not improvise it.

### 2. Install the sidecar

```bash
ssh <node> 'bash /tmp/awg3-sidecar.sh'          # dry run, prints the plan
ssh <node> 'bash /tmp/awg3-sidecar.sh --apply'
```

The incumbent interface keeps serving on 443 for the whole DKMS build. Read the
SUMMARY line: `ok=yes`, and `awg2_peers=<N>` is the parity target for the
cutover. Any failed check — stop, restore from the printed backup path.

If the node has multiple existing WireGuard interfaces and the script refuses
with a message about `--incumbent`, re-run naming the interface you pinned
above:

```bash
ssh <node> "bash /tmp/awg3-sidecar.sh --incumbent $OLD_IFACE"           # dry run
ssh <node> "bash /tmp/awg3-sidecar.sh --incumbent $OLD_IFACE --apply"
```

This is expected when a node has been converted before or serves multiple
profiles.

### 3. Prove the new interface — and then delete the test peer

Create a throwaway peer through the node API, load its config into a real
client, and connect it to `:8443`. **On the node:**

```bash
KEY=$(sudo grep -E '^API_TOKEN=' /etc/wireguard-api/.env | cut -d= -f2- | tr -d '"')
PORT=$(sudo grep -E '^API_PORT=' /etc/wireguard-api/.env | cut -d= -f2- | tr -d '"')
curl -s -H "key: $KEY" -H 'Content-Type: application/json' \
     -d '{"name":"awg3probe"}' "http://127.0.0.1:${PORT:-8080}/api/users/add"
```

Copy the `config` field out of the response, load it in a client, connect, then
check on the node:

```bash
if ! dump=$(sudo awg show "$NEW_IFACE" dump 2>&1); then
    printf 'GATE FAILED — could not read %s: %s\nDo NOT cut over.\n' "$NEW_IFACE" "$dump"
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

**Now delete the test peer. This is not optional.** It exists on the node but in
no database row, so the cutover's pool sync — which mirrors the node's *entire*
AWG3 user list — would claim it too, the clone would end up with N+1 configs
against a parity target of N, and the cutover would abort. Disconnect the test
client first, then:

```bash
curl -s -H "key: $KEY" -H 'Content-Type: application/json' \
     -d '{"name":"awg3probe"}' "http://127.0.0.1:${PORT:-8080}/api/users/delete"
```

Then confirm the interface is empty again — same construct, for the same reason
(`awg show ... | wc -l` prints 0 on a permission error, which here would be the
answer you want to see and therefore the one you must not trust):

```bash
if ! dump=$(sudo awg show "$NEW_IFACE" dump 2>&1); then
    printf 'CHECK FAILED — could not read %s: %s\n' "$NEW_IFACE" "$dump"
else
    printf '%s\n' "$dump" | awk 'NR>1 {c++} END {print "peers remaining: " c+0}'
fi
```

Must print `peers remaining: 0`.

`servers:awg3-cutover` prints both "created by this run" and "total AWG3 peers
on the node", so if you do forget, the parity error tells you which it was. But
the fix is still to delete the stray peer, delete the half-built clone row, and
re-run — the command refuses to build a second clone for the same node, on
purpose.

## Path A (premium) — take 443, then cut over

### A4. Wait for a natural zero

Poll until the incumbent reports **0** live peers. Nothing is retired, so this
is simply a quiet moment on a lightly-loaded node. Use the live-peer gate
command from "Counting live peers" above, in the shell where `$OLD_IFACE` is
set. Repeat until you see `live peers: 0` with no error prefix.

### A5. Take 443

Have the A6 command typed and ready before running this. **On your
workstation**, where `$OLD_IFACE` is exported:

```bash
# root@ nodes:
ssh <node> 'bash -s' < awg2-port443.sh -- --iface awg3 --old-iface "$OLD_IFACE" --apply
# ubuntu@ nodes (~10 of them — see "Naming the incumbent interface" above):
ssh <node> 'sudo bash -s' < awg2-port443.sh -- --iface awg3 --old-iface "$OLD_IFACE" --apply
```

Unlike the sidecar and preflight scripts, `awg2-port443.sh` has no
passwordless-sudo fallback of its own — it just checks `id -u` and exits with
`FAIL: must run as root` if that's not 0. Run as `ubuntu@` without `sudo`, it
dies before touching anything, right after you've confirmed the zero-live-peer
window you've been waiting for. Use whichever line matches how you connected
above; don't add `sudo` on a `root@` node just to be safe — root shells on
this fleet are not guaranteed to have `sudo` installed, and that would trade a
known-working invocation for an unverified one.

The script now refuses on its own if the incumbent still has a live peer, and
refuses if it cannot read that interface's peer table at all — a wrong
`--old-iface` no longer passes silently. `--force` overrides it and drops those
users; on Path A you should never need it.

It rewrites `SERVER_PORT` in the params file and `AWG_PORT` in the API env, so
every config issued from now carries `:443`. It rolls itself back on any failed
check.

### A6. Cut over the row — immediately

**On the backend box:**

```bash
php artisan servers:awg3-cutover --server-id=<id> --configs=<N> --apply
```

Run this straight after A5. Between the two, the active row is the AWG2 one
while its interface is already down, so a user allocated in that gap gets a
config for a dead interface. Seconds, one city — but do not leave it open.

The command probes the node and **refuses if the configs it issues are not on
:443**, which is what catches an A5 that was skipped or that silently failed.
Do not reach for `--allow-non-443` here; on Path A that refusal is telling you
the port move did not happen. Go and fix A5.

The clone is created `inactive`, seeded, checked against `--configs`, and only
then flipped to `active` in the same transaction that retires the old row. So
there is no moment where both rows serve, and no moment where an empty clone
sorts to the front of the location group.

If `--configs` disagrees with the legacy pool size the command prints both
numbers and stops. They are two different measurements — a node peer count from
when the sidecar ran, and a database row count from now — so a small difference
can be fine. When you have decided it is, re-run with `--accept-mismatch`. It
takes no TTY, so it works over a plain `ssh … 'php artisan …'`.

The pool is seeded while the node is already on 443, so its configs are correct
with no Endpoint rewrite needed.

## Path B (free) — cut over, drain, then take 443

### B4. Cut over at the traffic trough (backend box)

Confirm `servers:connect-check` is still paused before you start (the check
command in "Pause the crons"). From here until B6 the clone is deliberately
serving on a port some networks drop, and an unpaused connect-check will disable
it while the old row is already inactive — taking the whole city offline.

```bash
php artisan servers:awg3-cutover --server-id=<id> --configs=<N> --allow-non-443            # dry run
php artisan servers:awg3-cutover --server-id=<id> --configs=<N> --allow-non-443 --apply
```

`--allow-non-443` is required here and only here: it is how Path B says "yes, I
know this pool is being seeded on :8443, that is the plan". Without it the
command refuses, which is what protects Path A.

From here new allocations go to AWG3 on `:8443`. **This is the one window in the
rollout where users are affected:** networks that pass only UDP 443 cannot
connect to this city until B6. Measured 2026-08-09 — users who could not connect
had 588 past successes on :443 and 9 on :8081, same node and IP. Keep it short.

### B5. Drain

Live users keep their AWG2 configs until they reconnect; every reconnect
resolves the location group to the AWG3 clone and releases the old config back
to the pool. Poll live peers on the incumbent, using the live-peer gate command
from "Counting live peers", until it reads `live peers: 0` with no error prefix.

This takes hours. If it runs past the 12-hour cron pause, re-run the pause
command before the TTL expires.

### B6. Take 443, with a grace redirect, then fix the stored endpoints

The clone's stored configs all say `:8443`. The moment the port moves, nothing
is listening there — so between the move and the endpoint rewrite, every user
holding one of those configs cannot connect. `awg2-port443.sh` has
`--grace-redirect` for exactly this gap: it NAT-forwards the old port to 443 on
the *same* interface with the *same* keys, so stale configs keep working while
you rewrite them.

Take 443 **with** the redirect, **on your workstation**:

```bash
# root@ nodes:
ssh <node> 'bash -s' < awg2-port443.sh -- --iface awg3 --old-iface "$OLD_IFACE" --grace-redirect --apply
# ubuntu@ nodes (~10 of them — see "Naming the incumbent interface" above):
ssh <node> 'sudo bash -s' < awg2-port443.sh -- --iface awg3 --old-iface "$OLD_IFACE" --grace-redirect --apply
```

Same root requirement as A5: `awg2-port443.sh` has no sudo fallback of its
own, so on an `ubuntu@` node the plain form dies with `FAIL: must run as
root` before it takes 443. Use the line matching how you connected.

Then, **on the backend box**, rewrite just the `Endpoint` line on that row's
configs — the peer keys are unchanged, so the pool does **not** need
regenerating.

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

Finally remove the redirect, once the rewrite is done and traffic on the old
port has stopped. On the node:

```bash
sudo iptables -t nat -L PREROUTING -n --line-numbers | grep 8443     # confirm it is there
sudo iptables -t nat -D PREROUTING -p udp --dport 8443 -j REDIRECT --to-port 443
sudo iptables -D INPUT -p udp --dport 8443 -j ACCEPT
sudo iptables -t nat -L PREROUTING -n | grep 8443 || echo "redirect removed"
```

Leaving it in place is not dangerous — it points at the same interface and the
same keys — but it keeps a second door open on a node whose whole purpose is to
be hard to fingerprint. Remove it.

### B7. Check the clone is still active (backend box)

The `:8443` window scores badly, so verify `servers:connect-check` did not
disable the clone despite the pause:

```bash
php artisan tinker --execute='
$s = App\Models\Server::find(<clone-id>);
echo $s->id, " ", $s->ip, " status=", $s->status, " awg3=", (int) $s->is_support_awg_third, "\n";
'
```

`status=active` is the only acceptable answer. If it reads `inactive`, the city
is offline right now — re-activate it and clear the strike counter so it is not
disabled again on the next run:

```bash
php artisan tinker --execute='
App\Models\Server::find(<clone-id>)->update(["status" => "active"]);
Illuminate\Support\Facades\Cache::forget("servers:connect-check:strikes");
echo "reactivated\n";
'
```

## Both paths: after the cutover

**Re-enable all three crons.** Nothing below is safe to leave paused, and the
conversion is not finished until this is done:

```bash
php artisan tinker --execute='
foreach (["configs:cleanup-stale", "servers:connect-check", "servers:health-check"] as $name) {
    $e = collect(app(Illuminate\Console\Scheduling\Schedule::class)->events())
        ->first(fn ($ev) => str_contains((string) $ev->command, $name));
    $e->mutex->forget($e);
    echo $name, " still paused: ", var_export($e->mutex->exists($e), true), "\n";
}
'
```

All three must print `still paused: false`.

`configs:cleanup-stale` and `servers:health-check` are both safe again the
moment the old row is `inactive` — they only act on `active` servers by
design. That is why the pause only has to cover the
sidecar→cutover window.

**Never run "Sync Server", "Add Users" or "Delete All Users" on the retired
row.** The node API serves AWG3, so any of them would write AWG3 configs into
the retired AWG2 row and delete the config rows live users still hold. Those
three Filament actions are now disabled on any row that is not `active`, and
hovering one tells you why — but the retired row goes inactive at cutover, so
do not go re-activating it to "have a look".

Soft-delete the retired row once its interface is gone.

## Rollback

Before AWG3 takes 443 — free on both paths, from your workstation:

```bash
# root@ nodes:
ssh <node> "systemctl stop awg-quick@$NEW_IFACE; awg-quick up $OLD_IFACE"
# ubuntu@ nodes (~10 of them — see "Naming the incumbent interface" above):
ssh <node> "sudo systemctl stop awg-quick@$NEW_IFACE; sudo awg-quick up $OLD_IFACE"
```

Neither `systemctl` nor `awg-quick` self-elevates, so on an `ubuntu@` node the
plain form fails on a permission error instead of rolling anything back. Use
the line matching how you connected.

`awg2-port443.sh` rolls itself back automatically on a failed check, restoring
the config, params and API env and re-enabling the old interface.

After the row cutover, reverse the flip, on the backend box:

```bash
php artisan tinker --execute='App\Models\Server::find(<old-id>)->update(["status" => "active"]); App\Models\Server::find(<clone-id>)->update(["status" => "inactive"]);'
```

The old row never had `is_support_awg_third` set, so there is nothing to un-set
— it becomes visible to every client again the moment it is active.

Live users were never moved, so there is nothing to undo on the node itself.
Once the old interface is torn down and its configs are gone, that node is
committed.
