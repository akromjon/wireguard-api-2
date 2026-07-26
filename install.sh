#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color
SMTP_BLOCK_PORTS=(25 465 587)

add_firewall_rule() {
    local FIREWALL_BIN=$1
    shift

    if ! command -v "$FIREWALL_BIN" &> /dev/null; then
        if [[ "$FIREWALL_BIN" == "iptables" ]]; then
            echo -e "${RED}${FIREWALL_BIN} not found. Cannot install outbound SMTP block.${NC}"
            return 1
        fi
        return 0
    fi

    if "$FIREWALL_BIN" -C "$@" 2> /dev/null; then
        return 0
    fi

    "$FIREWALL_BIN" -I "$@"
}

append_smtp_block_to_vpn_config() {
    local VPN_CONFIG_FILE=$1
    local VPN_INTERFACE=$2
    local SMTP_BLOCK_FILE
    local TMP_CONFIG
    local CLEAN_CONFIG=""
    local SOURCE_CONFIG="$VPN_CONFIG_FILE"

    SMTP_BLOCK_FILE=$(mktemp) || return 1
    TMP_CONFIG=$(mktemp) || {
        rm -f "$SMTP_BLOCK_FILE"
        return 1
    }

    {
        echo ""
        echo "# VIPN outbound SMTP block"
        for PORT in "${SMTP_BLOCK_PORTS[@]}"; do
            echo "PostUp = command -v iptables >/dev/null && (iptables -C FORWARD -i ${VPN_INTERFACE} -p tcp --dport ${PORT} -j REJECT 2>/dev/null || iptables -I FORWARD -i ${VPN_INTERFACE} -p tcp --dport ${PORT} -j REJECT) || true"
            echo "PostUp = command -v iptables >/dev/null && (iptables -C OUTPUT -p tcp --dport ${PORT} -j REJECT 2>/dev/null || iptables -I OUTPUT -p tcp --dport ${PORT} -j REJECT) || true"
            echo "PostUp = command -v ip6tables >/dev/null && (ip6tables -C FORWARD -i ${VPN_INTERFACE} -p tcp --dport ${PORT} -j REJECT 2>/dev/null || ip6tables -I FORWARD -i ${VPN_INTERFACE} -p tcp --dport ${PORT} -j REJECT) || true"
            echo "PostUp = command -v ip6tables >/dev/null && (ip6tables -C OUTPUT -p tcp --dport ${PORT} -j REJECT 2>/dev/null || ip6tables -I OUTPUT -p tcp --dport ${PORT} -j REJECT) || true"
            echo "PostDown = command -v iptables >/dev/null && iptables -D FORWARD -i ${VPN_INTERFACE} -p tcp --dport ${PORT} -j REJECT 2>/dev/null || true"
            echo "PostDown = command -v iptables >/dev/null && iptables -D OUTPUT -p tcp --dport ${PORT} -j REJECT 2>/dev/null || true"
            echo "PostDown = command -v ip6tables >/dev/null && ip6tables -D FORWARD -i ${VPN_INTERFACE} -p tcp --dport ${PORT} -j REJECT 2>/dev/null || true"
            echo "PostDown = command -v ip6tables >/dev/null && ip6tables -D OUTPUT -p tcp --dport ${PORT} -j REJECT 2>/dev/null || true"
        done
    } > "$SMTP_BLOCK_FILE"

    if grep -q "^# VIPN outbound SMTP block$" "$VPN_CONFIG_FILE"; then
        echo -e "${YELLOW}Refreshing outbound SMTP block in ${VPN_CONFIG_FILE}.${NC}"
        CLEAN_CONFIG=$(mktemp) || {
            rm -f "$SMTP_BLOCK_FILE" "$TMP_CONFIG"
            return 1
        }

        if ! awk '
            /^# VIPN outbound SMTP block$/ {
                skipping = 1
                next
            }
            skipping && /^Post(Up|Down) = command -v ip6?tables / {
                next
            }
            {
                skipping = 0
                print
            }
        ' "$VPN_CONFIG_FILE" > "$CLEAN_CONFIG"; then
            rm -f "$SMTP_BLOCK_FILE" "$TMP_CONFIG" "$CLEAN_CONFIG"
            return 1
        fi
        SOURCE_CONFIG=$CLEAN_CONFIG
    fi

    if ! awk -v block_file="$SMTP_BLOCK_FILE" '
        BEGIN {
            while ((getline line < block_file) > 0) {
                block = block line ORS
            }
            inserted = 0
        }
        !inserted && /^\[Peer\]$/ {
            printf "%s", block
            inserted = 1
        }
        { print }
        END {
            if (!inserted) {
                printf "%s", block
            }
        }
    ' "$SOURCE_CONFIG" > "$TMP_CONFIG"; then
        rm -f "$SMTP_BLOCK_FILE" "$TMP_CONFIG" "$CLEAN_CONFIG"
        return 1
    fi

    cp "$TMP_CONFIG" "$VPN_CONFIG_FILE"
    rm -f "$SMTP_BLOCK_FILE" "$TMP_CONFIG" "$CLEAN_CONFIG"
}

configure_outbound_smtp_block() {
    local VPN_INTERFACE=""
    local VPN_CONFIG_FILE=""

    case "$VPN_TYPE" in
        amneziawg)
            if [[ -f /etc/amnezia/amneziawg/params ]]; then
                # shellcheck disable=SC1091
                source /etc/amnezia/amneziawg/params
                VPN_INTERFACE="${SERVER_AWG_NIC:-}"
                VPN_CONFIG_FILE="/etc/amnezia/amneziawg/${VPN_INTERFACE}.conf"
            fi
            ;;
        wireguard)
            if [[ -f /etc/wireguard/params ]]; then
                # shellcheck disable=SC1091
                source /etc/wireguard/params
                VPN_INTERFACE="${SERVER_WG_NIC:-}"
                VPN_CONFIG_FILE="/etc/wireguard/${VPN_INTERFACE}.conf"
            fi
            ;;
    esac

    if [[ -z "$VPN_INTERFACE" || ! -f "$VPN_CONFIG_FILE" ]]; then
        echo -e "${RED}Could not find the installed ${VPN_TYPE} interface/config for outbound SMTP blocking.${NC}"
        return 1
    fi

    echo -e "${YELLOW}Blocking outbound SMTP ports for VPN traffic: ${SMTP_BLOCK_PORTS[*]}${NC}"

    for PORT in "${SMTP_BLOCK_PORTS[@]}"; do
        add_firewall_rule iptables FORWARD -i "$VPN_INTERFACE" -p tcp --dport "$PORT" -j REJECT || return 1
        add_firewall_rule iptables OUTPUT -p tcp --dport "$PORT" -j REJECT || return 1
        add_firewall_rule ip6tables FORWARD -i "$VPN_INTERFACE" -p tcp --dport "$PORT" -j REJECT || return 1
        add_firewall_rule ip6tables OUTPUT -p tcp --dport "$PORT" -j REJECT || return 1
    done

    append_smtp_block_to_vpn_config "$VPN_CONFIG_FILE" "$VPN_INTERFACE"
    echo -e "${GREEN}Outbound SMTP block installed for ${VPN_INTERFACE}.${NC}"
}

configure_conntrack() {
    # NAT-gateway tuning. The default nf_conntrack table (65536) fills up under
    # ~100+ concurrent VPN users, causing "nf_conntrack: table full, dropping
    # packet" and severe slowness. We size the table to the node's real
    # capacity (configs provisioned x peak flows per user), bounded by a RAM
    # safety cap, then recycle stale flows faster, persist, and monitor at 80%.
    # Tunable via env: CONNTRACK_CONFIGS_PER_NODE, CONNTRACK_FLOWS_PER_USER.
    local configs flows kb ram_bytes max hash cap
    configs="${CONNTRACK_CONFIGS_PER_NODE:-1000}"
    flows="${CONNTRACK_FLOWS_PER_USER:-512}"
    kb=$(awk '/MemTotal/{print $2}' /proc/meminfo)
    ram_bytes=$(( kb * 1024 ))

    # size by real capacity: configs x peak-flows-per-user
    max=$(( configs * flows ))

    # RAM safety cap: a full table (~320 bytes/entry) must not exceed 15% of RAM
    cap=$(( ram_bytes * 15 / 100 / 320 ))
    [[ "$max" -gt "$cap" ]] && max="$cap"

    # floor so small boxes still get a usable table
    [[ "$max" -lt 131072 ]] && max=131072

    # hashsize = max/4 (best-practice ratio)
    hash=$(( max / 4 ))
    [[ "$hash" -lt 32768 ]] && hash=32768

    echo -e "${YELLOW}Tuning nf_conntrack (max=${max}, hashsize=${hash})...${NC}"

    cat > /etc/sysctl.d/99-conntrack.conf <<CONNTRACK
net.netfilter.nf_conntrack_max = ${max}
net.netfilter.nf_conntrack_tcp_timeout_established = 86400
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
net.netfilter.nf_conntrack_udp_timeout = 30
net.netfilter.nf_conntrack_udp_timeout_stream = 120
CONNTRACK

    # hashsize must be set at module load; persist via modprobe.d
    echo "options nf_conntrack hashsize=${hash}" > /etc/modprobe.d/nf_conntrack.conf

    # ensure the module loads at boot BEFORE systemd-sysctl, so nf_conntrack_max
    # reliably applies on every server/provider regardless of boot order
    echo "nf_conntrack" > /etc/modules-load.d/nf_conntrack.conf

    # apply immediately (no reboot)
    modprobe nf_conntrack 2>/dev/null || true
    echo "${hash}" > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || true
    sysctl -q -p /etc/sysctl.d/99-conntrack.conf 2>/dev/null || true

    # monitor: warn at >=80% table use, AND flag any single user hogging
    # connections (>=2000) so an abuser is visible before hitting the cap
    cat > /usr/local/bin/conntrack-watch.sh <<'WATCH'
#!/bin/bash
max=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null) || exit 0
cnt=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null) || exit 0
[[ "${max:-0}" -gt 0 ]] || exit 0
pct=$(( cnt * 100 / max ))
[[ "$pct" -ge 80 ]] && logger -t conntrack-watch "WARNING table ${cnt}/${max} (${pct}%)"
if command -v conntrack >/dev/null 2>&1; then
  # derive the VPN client subnet prefix from this node's params (default 10.66)
  for p in /etc/amnezia/amneziawg/params /etc/wireguard/params; do [ -f "$p" ] && . "$p" 2>/dev/null && break; done
  ip4="${SERVER_AWG_IPV4:-${SERVER_WG_IPV4:-10.66.66.1}}"
  pre="$(printf '%s' "$ip4" | cut -d. -f1-2)"; pre_re="${pre//./\\.}"
  conntrack -L 2>/dev/null | grep -oE "src=${pre_re}\.[0-9.]+" | sort | uniq -c | sort -rn \
    | awk '$1>=2000{print $2" "$1}' | while read ip c; do logger -t conntrack-watch "HOG ${ip#src=} ${c}conn"; done
fi
exit 0
WATCH
    chmod +x /usr/local/bin/conntrack-watch.sh
    echo "*/5 * * * * root /usr/local/bin/conntrack-watch.sh" > /etc/cron.d/conntrack-watch

    echo -e "${GREEN}nf_conntrack tuned: max=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null), hashsize=$(cat /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null).${NC}"
}

configure_abuse_protection() {
    # Per-user connection cap so one abusive client cannot exhaust the shared
    # conntrack table for everyone. Default 4000 concurrent connections per VPN
    # client IP (generous: normal users sit in the hundreds). Tunable via
    # CONNTRACK_PER_USER_CAP. Persisted as a systemd unit applied after the
    # tunnel is up. The `conntrack` tool powers the top-talker alert.
    local cap nic quicksvc
    cap="${CONNTRACK_PER_USER_CAP:-4000}"
    # backend-aware interface + tunnel service (amneziawg=awg0/awg-quick, wireguard=wg0/wg-quick)
    if [[ "${VPN_TYPE}" == "wireguard" ]]; then
        [[ -f /etc/wireguard/params ]] && . /etc/wireguard/params
        nic="${SERVER_WG_NIC:-wg0}"; quicksvc="wg-quick@${nic}.service"
    else
        [[ -f /etc/amnezia/amneziawg/params ]] && . /etc/amnezia/amneziawg/params
        nic="${SERVER_AWG_NIC:-awg0}"; quicksvc="awg-quick@${nic}.service"
    fi

    command -v conntrack >/dev/null 2>&1 || DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=60 install -y conntrack >/dev/null 2>&1 || true

    echo -e "${YELLOW}Installing per-user connection cap (${cap}/user) on ${nic}...${NC}"

    cat > /etc/default/awg-connlimit <<DEFAULT
AWG_CONN_CAP=${cap}
AWG_NIC=${nic}
DEFAULT

    cat > /usr/local/bin/awg-connlimit.sh <<'CL'
#!/bin/bash
CAP=4000
NIC=awg0
[ -f /etc/default/awg-connlimit ] && . /etc/default/awg-connlimit
CAP="${AWG_CONN_CAP:-$CAP}"; NIC="${AWG_NIC:-$NIC}"
run() {
  local act="$1" pair ipt mask
  for pair in "iptables 32" "ip6tables 128"; do
    set -- $pair; ipt="$1"; mask="$2"
    if [ "$act" = add ]; then
      # TCP: reject NEW connections above the cap (existing stay up). connlimit counts
      # ALL flows per source IP, so TCP+UDP share one per-user total.
      $ipt -C FORWARD -i "$NIC" -p tcp --syn -m connlimit --connlimit-above "$CAP" --connlimit-mask "$mask" -j REJECT --reject-with tcp-reset 2>/dev/null \
        || $ipt -I FORWARD 1 -i "$NIC" -p tcp --syn -m connlimit --connlimit-above "$CAP" --connlimit-mask "$mask" -j REJECT --reject-with tcp-reset 2>/dev/null || true
      # UDP: drop NEW flows above the cap (covers QUIC / UDP torrents that TCP --syn misses)
      $ipt -C FORWARD -i "$NIC" -p udp -m connlimit --connlimit-above "$CAP" --connlimit-mask "$mask" -j DROP 2>/dev/null \
        || $ipt -I FORWARD 1 -i "$NIC" -p udp -m connlimit --connlimit-above "$CAP" --connlimit-mask "$mask" -j DROP 2>/dev/null || true
    else
      $ipt -D FORWARD -i "$NIC" -p tcp --syn -m connlimit --connlimit-above "$CAP" --connlimit-mask "$mask" -j REJECT --reject-with tcp-reset 2>/dev/null || true
      $ipt -D FORWARD -i "$NIC" -p udp -m connlimit --connlimit-above "$CAP" --connlimit-mask "$mask" -j DROP 2>/dev/null || true
    fi
  done
}
case "$1" in add) run add;; del) run del;; *) echo "usage: $0 add|del";; esac
CL
    chmod +x /usr/local/bin/awg-connlimit.sh

    cat > /etc/systemd/system/awg-connlimit.service <<UNIT
[Unit]
Description=Per-user connection cap for ${nic}
After=${quicksvc} network-online.target
Wants=${quicksvc}
PartOf=${quicksvc}
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/awg-connlimit.sh add
ExecStop=/usr/local/bin/awg-connlimit.sh del
[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable --now awg-connlimit.service >/dev/null 2>&1 || /usr/local/bin/awg-connlimit.sh add

    echo -e "${GREEN}Per-user connection cap active (${cap}/user) on ${nic}.${NC}"
}

RELEASE_REPO="akromjon/wireguard-api-2"

detect_binary_filename() {
    case "$(uname -sm)" in
        "Linux x86_64") echo "wireguard-linux-amd64" ;;
        "Linux i686")   echo "wireguard-linux-386" ;;
        "Linux armv7l") echo "wireguard-linux-arm" ;;
        "Linux aarch64") echo "wireguard-linux-arm64" ;;
        *) echo "" ;;
    esac
}

# The legacy migration helper remains below only because this file was
# derived from v1. It is intentionally unreachable in V2; existing nodes
# must be handled by the v1 repository.
migrate_to_sixteen_allocator() {
    local TAG="${SIXTEEN_TAG:-latest}"
    local INSTALL_DIR="/usr/local/bin"
    local NIC CONF IP WG_SVC FILENAME URL TMP

    echo -e "${GREEN}== Sixteen-allocator migration ==${NC}"

    # 1. Detect VPN backend, interface, config, server IPv4.
    if [[ -f /etc/amnezia/amneziawg/params ]]; then
        # shellcheck disable=SC1091
        source /etc/amnezia/amneziawg/params
        NIC="${SERVER_AWG_NIC}"; IP="${SERVER_AWG_IPV4}"
        CONF="/etc/amnezia/amneziawg/${NIC}.conf"; WG_SVC="awg-quick@${NIC}"
    elif [[ -f /etc/wireguard/params ]]; then
        # shellcheck disable=SC1091
        source /etc/wireguard/params
        NIC="${SERVER_WG_NIC}"; IP="${SERVER_WG_IPV4}"
        CONF="/etc/wireguard/${NIC}.conf"; WG_SVC="wg-quick@${NIC}"
    else
        echo -e "${RED}No WireGuard/AmneziaWG params found — is this node installed?${NC}"; return 1
    fi
    if [[ -z "$NIC" || -z "$IP" || ! -f "$CONF" ]]; then
        echo -e "${RED}Could not resolve interface ($NIC), IP ($IP) or config ($CONF).${NC}"; return 1
    fi
    echo -e "${YELLOW}Backend interface=${NIC} ip=${IP} conf=${CONF}${NC}"

    local NET16 NET24
    NET16="$(echo "$IP" | cut -d. -f1-2).0.0/16"
    NET24="$(echo "$IP" | cut -d. -f1-3).0/24"

    # 2. Widen the interface to /16 FIRST — before the new binary goes live —
    #    so any address it later hands out beyond the original /24 will route.
    #    The old binary keeps allocating inside the /24 in the meantime, which
    #    is still valid within the /16, so there is no window of broken peers.

    # 2a. Persist in the config (IPv4 only; leave IPv6 /64). Also widen the
    #     firewalld masquerade source in the config so a reboot/awg-quick restart
    #     keeps /16 instead of re-adding /24.
    if grep -qE "^Address = ${IP}/16([,/[:space:]]|$)" "$CONF"; then
        echo -e "${GREEN}Config already /16.${NC}"
    else
        sed -i -E "s#^(Address = ${IP})/24#\1/16#" "$CONF"
        echo -e "${GREEN}Config Address set to ${IP}/16.${NC}"
    fi
    sed -i "s#source address=${NET24}#source address=${NET16}#g" "$CONF" 2>/dev/null || true

    # 2b. Apply live, gap-free: add /16 BEFORE removing /24 so the server is
    #     never without a covering address. WG peers are independent of the
    #     interface address, so tunnels are not dropped.
    ip addr replace "${IP}/16" dev "${NIC}"
    ip addr del "${IP}/24" dev "${NIC}" 2>/dev/null || true
    echo -e "${GREEN}Live interface set to ${IP}/16.${NC}"

    # 2c. firewalld runtime masquerade (iptables MASQUERADE is unscoped — no-op).
    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --remove-rich-rule="rule family=ipv4 source address=${NET24} masquerade" 2>/dev/null || true
        firewall-cmd --add-rich-rule="rule family=ipv4 source address=${NET16} masquerade" 2>/dev/null || true
        firewall-cmd --runtime-to-permanent 2>/dev/null || true
        echo -e "${GREEN}firewalld masquerade widened to ${NET16}.${NC}"
    fi

    # 3. NOW download + swap the new /16-allocator binary.
    FILENAME="$(detect_binary_filename)"
    [[ -z "$FILENAME" ]] && { echo -e "${RED}Unsupported arch: $(uname -sm)${NC}"; return 1; }
    if [[ "$TAG" == "latest" ]]; then
        URL="https://github.com/${RELEASE_REPO}/releases/latest/download/${FILENAME}"
    else
        URL="https://github.com/${RELEASE_REPO}/releases/download/${TAG}/${FILENAME}"
    fi
    TMP="$(mktemp)"
    echo -e "${YELLOW}Downloading ${FILENAME} (${TAG})...${NC}"
    if ! curl -sSLf "$URL" -o "$TMP" || [[ ! -s "$TMP" ]]; then
        echo -e "${RED}Download failed or empty: ${URL}${NC}"; rm -f "$TMP"; return 1
    fi
    chmod +x "$TMP"
    mv "$TMP" "${INSTALL_DIR}/wireguard" && chmod +x "${INSTALL_DIR}/wireguard"
    echo -e "${GREEN}Binary updated: ${INSTALL_DIR}/wireguard${NC}"

    # 4. Restart the API service.
    systemctl restart wireguard.service 2>/dev/null || true
    if systemctl is-active --quiet wireguard.service; then
        echo -e "${GREEN}wireguard.service restarted.${NC}"
    else
        echo -e "${YELLOW}Warning: wireguard.service not active — journalctl -u wireguard.service${NC}"
    fi

    # 5. Verify.
    echo -e "${YELLOW}Verification:${NC}"
    if ip -4 addr show "$NIC" | grep -qE "inet ${IP}/16"; then
        echo -e "${GREEN}  ✓ interface ${NIC} is ${IP}/16${NC}"
    else
        echo -e "${RED}  ✗ interface ${NIC} is NOT /16 — check manually${NC}"
    fi
    echo -e "${GREEN}Migration complete. New users allocate across the /16 (~64k addresses).${NC}"
    echo -e "${YELLOW}Next: raise this server's max_connections in the panel to a resource-realistic value.${NC}"
    return 0
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run as root${NC}"
  exit 1
fi

# V2 deliberately does not migrate existing nodes. The v1 repository owns
# legacy-node migrations; using this installer against one would blur the
# protocol boundary and could start an incompatible API binary.
if [[ "${1:-}" == "sixteen-allocator" ]]; then
	echo -e "${RED}V2 does not migrate existing AWG1/WireGuard nodes.${NC}" >&2
	echo "Use the v1 repository's migration procedure for legacy nodes." >&2
	exit 2
fi

echo -e "${GREEN}WireGuard API V2 / AmneziaWG 2.0 Installer${NC}"
echo "This script installs the AWG2 stack on a clean VPS."
echo "Legacy AWG1 nodes are not modified by this installer."
VPN_TYPE="amneziawg"
INSTALLER_SCRIPT="amneziawg-install.sh"

echo -e "${GREEN}Selected: ${VPN_TYPE}${NC}"
echo ""

# Install git if not already installed
if ! command -v git &> /dev/null; then
    echo -e "${YELLOW}Git not found. Installing git...${NC}"
    if command -v apt-get &> /dev/null; then
        apt-get update && apt-get install -y git
    elif command -v yum &> /dev/null; then
        yum install -y git
    elif command -v dnf &> /dev/null; then
        dnf install -y git
    elif command -v apk &> /dev/null; then
        apk add git
    else
        echo -e "${RED}Could not install git. Please install git manually and try again.${NC}"
        exit 1
    fi
fi

# Create a temporary directory
TEMP_DIR=$(mktemp -d)
echo -e "${YELLOW}Cloning repository...${NC}"

# Clone the repository
if git clone https://github.com/akromjon/wireguard-api-2.git "$TEMP_DIR"; then
    echo -e "${GREEN}Repository cloned successfully.${NC}"
else
    echo -e "${RED}Failed to clone repository.${NC}"
    rm -rf "$TEMP_DIR"
    exit 1
fi

# Navigate to the repository directory
cd "$TEMP_DIR" || exit 1

# Make the installer script executable
chmod +x "$INSTALLER_SCRIPT"

# Run the installer script
echo -e "${YELLOW}Running the ${VPN_TYPE} installer script...${NC}"
if ./"$INSTALLER_SCRIPT"; then
    echo -e "${GREEN}Installation completed successfully.${NC}"
else
    echo -e "${RED}Installation failed.${NC}"
    exit 1
fi

if ! configure_outbound_smtp_block; then
    echo -e "${RED}Failed to install outbound SMTP block.${NC}"
    cd - > /dev/null || exit 1
    rm -rf "$TEMP_DIR"
    exit 1
fi

# Non-fatal: NAT connection-tracking tuning so the node survives high user counts.
configure_conntrack || echo -e "${RED}Warning: nf_conntrack tuning failed (non-fatal).${NC}"

# Non-fatal: per-user connection cap so one client can't starve the shared table.
configure_abuse_protection || echo -e "${RED}Warning: abuse-protection setup failed (non-fatal).${NC}"

# Clean up
cd - > /dev/null || exit 1
rm -rf "$TEMP_DIR"

echo -e "${GREEN}WireGuard API has been installed successfully!${NC}"
exit 0
