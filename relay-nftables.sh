#!/bin/bash
# Turn a relay box into a kernel-level UDP forwarder: clients hit the relay's
# public IP, the kernel rewrites the destination to the real node. Replaces a
# userspace proxy (nginx stream, socat, gost), which copies every packet into
# userspace and back and caps out on worker_connections long before CPU does.
#
#   scp relay-nftables.sh <relay>:/tmp/
#   ssh <relay> 'bash /tmp/relay-nftables.sh --node 141.227.190.94'          # plan only
#   ssh <relay> 'bash /tmp/relay-nftables.sh --node 141.227.190.94 --apply'
#
# Without --apply it prints the plan and changes nothing.
#
#   --node <ip>        node to forward to (required)
#   --port <n>         UDP port on both sides (default 443)
#   --stop-nginx       stop+disable nginx after the rules are in place
#   --uninstall        remove the relay table, sysctls and units
#   --apply            actually make changes
#
# NOTE ON CLIENT IPs: this masquerades, so the node sees every relayed user as
# the relay's IP. WireGuard rate-limits handshakes per source IP (~20/s), so a
# single relay IP starts throttling somewhere in the high hundreds of peers -
# rekeys alone are ~12/s at 1500 peers. Spread users over several relay IPs, or
# preserve the client address with a GRE/WG tunnel plus routing instead of NAT.
set -Eeuo pipefail

NODE_IP=""
PORT=443
APPLY=0
STOP_NGINX=0
UNINSTALL=0
TABLE=chop_relay
SYSCTL_FILE=/etc/sysctl.d/99-chop-relay.conf
NFT_FILE=/etc/nftables.conf

while [[ $# -gt 0 ]]; do
	case "$1" in
	--node)
		NODE_IP=$2
		shift 2
		;;
	--port)
		PORT=$2
		shift 2
		;;
	--stop-nginx)
		STOP_NGINX=1
		shift
		;;
	--uninstall)
		UNINSTALL=1
		shift
		;;
	--apply)
		APPLY=1
		shift
		;;
	*)
		echo "unknown argument: $1" >&2
		exit 2
		;;
	esac
done

say() { printf '  %s\n' "$*"; }
run() {
	if [[ $APPLY -eq 1 ]]; then
		"$@"
	else
		printf '  would run: %s\n' "$*"
	fi
}

# Validate arguments before demanding root, so a mistyped flag fails clearly
# instead of failing on privileges and hiding the real problem.
if [[ $UNINSTALL -eq 0 ]]; then
	[[ -n $NODE_IP ]] || {
		echo "--node <ip> is required" >&2
		exit 2
	}
	[[ $NODE_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
		echo "--node must be an IPv4 address, got: $NODE_IP" >&2
		exit 2
	}
	if [[ ! $PORT =~ ^[0-9]+$ ]] || ((PORT < 1 || PORT > 65535)); then
		echo "--port must be 1-65535, got: $PORT" >&2
		exit 2
	fi
fi

[[ $EUID -eq 0 ]] || {
	echo "must run as root" >&2
	exit 1
}

if [[ $UNINSTALL -eq 1 ]]; then
	echo "=== uninstalling relay ==="
	run nft delete table ip "$TABLE" 2>/dev/null || say "table $TABLE not present"
	run rm -f "$SYSCTL_FILE"
	run sysctl --system >/dev/null
	say "removed table + sysctls. nftables.conf left alone - edit it if it referenced $TABLE."
	exit 0
fi

WAN=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'dev \K\S+' || true)
[[ -n $WAN ]] || {
	echo "could not determine WAN interface" >&2
	exit 1
}
RELAY_IP=$(ip -4 addr show dev "$WAN" | grep -oP 'inet \K[0-9.]+' | head -1)

echo "=== plan ==="
say "relay      : $RELAY_IP  (iface $WAN)"
say "forward    : udp/$PORT -> $NODE_IP:$PORT"
say "method     : nftables nat (kernel), replaces userspace proxying"
say "apply      : $([[ $APPLY -eq 1 ]] && echo yes || echo 'NO - dry run')"
echo

echo "=== current userspace listener on udp/$PORT ==="
ss -lunp 2>/dev/null | grep ":$PORT " | sed 's/^/  /' || say "(none)"
echo

command -v nft >/dev/null 2>&1 || {
	echo "=== installing nftables ==="
	run apt-get update -qq
	run apt-get install -y -qq nftables
}

echo "=== reachability to node ==="
if ping -c 2 -W 2 "$NODE_IP" >/dev/null 2>&1; then
	say "ICMP to $NODE_IP ok"
else
	say "WARNING: no ICMP reply from $NODE_IP (may still be fine if it filters ping)"
fi
echo

# Forwarding + conntrack. One UDP conntrack entry per relayed client, so the
# table has to be big enough for the peer count and the entries must outlive
# the 25s PersistentKeepalive our configs ship with.
echo "=== sysctl ==="
say "writing $SYSCTL_FILE"
if [[ $APPLY -eq 1 ]]; then
	cat >"$SYSCTL_FILE" <<-EOF
		net.ipv4.ip_forward = 1
		net.netfilter.nf_conntrack_max = 262144
		net.netfilter.nf_conntrack_udp_timeout = 60
		net.netfilter.nf_conntrack_udp_timeout_stream = 180
	EOF
	modprobe nf_conntrack 2>/dev/null || true
	sysctl --system >/dev/null
	say "ip_forward now $(cat /proc/sys/net/ipv4/ip_forward)"
	say "conntrack_max now $(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo '?')"
else
	say "would set ip_forward=1, nf_conntrack_max=262144, udp timeouts 60/180"
fi
echo

echo "=== nftables rules ==="
NFT_RULES=$(
	cat <<-EOF
		table ip $TABLE {
			chain prerouting {
				type nat hook prerouting priority dstnat; policy accept;
				iifname "$WAN" udp dport $PORT dnat to $NODE_IP:$PORT
			}
			chain postrouting {
				type nat hook postrouting priority srcnat; policy accept;
				ip daddr $NODE_IP udp dport $PORT masquerade
			}
		}
	EOF
)
printf '%s\n' "$NFT_RULES" | sed 's/^/  /'
echo

if [[ $APPLY -eq 1 ]]; then
	nft delete table ip "$TABLE" 2>/dev/null || true
	printf '%s\n' "$NFT_RULES" | nft -f -
	say "rules loaded"

	# Persist. Keep any existing ruleset; append ours if it is not referenced.
	if [[ -f $NFT_FILE ]] && grep -q "table ip $TABLE" "$NFT_FILE"; then
		say "$NFT_FILE already references $TABLE - leaving it"
	else
		cp -a "$NFT_FILE" "$NFT_FILE.bak-$(date +%s)" 2>/dev/null || true
		printf '\n%s\n' "$NFT_RULES" >>"$NFT_FILE"
		say "appended to $NFT_FILE (backup taken)"
	fi
	systemctl enable nftables >/dev/null 2>&1 || true
else
	say "would load rules and append them to $NFT_FILE"
fi
echo

if [[ $STOP_NGINX -eq 1 ]]; then
	echo "=== nginx ==="
	# DNAT happens in prerouting, before local socket lookup, so nginx goes
	# inert the moment the rules load. Stopping it just frees the memory and
	# stops it looking like the relay to the next person who reads the box.
	run systemctl stop nginx
	run systemctl disable nginx
	echo
fi

echo "=== verify ==="
if [[ $APPLY -eq 1 ]]; then
	say "active rules:"
	nft list table ip "$TABLE" 2>/dev/null | grep -E 'dnat|masquerade' | sed 's/^/    /'
	say "ip_forward = $(cat /proc/sys/net/ipv4/ip_forward)"
	say "conntrack  = $(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo '?') / $(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo '?')"
	echo
	say "watch it work (packet counters should climb):"
	say "  watch -n2 'nft list table ip $TABLE'"
	say "rollback:"
	say "  bash $0 --uninstall --apply"
else
	echo
	say "dry run only. re-run with --apply to make these changes."
fi
