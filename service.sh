#!/bin/bash

set -e
# github: https://github.com/akromjon/wireguard-api-2
RELEASE_REPO=${RELEASE_REPO:-akromjon/wireguard-api-2}
RELEASE_TAG=${WIREGUARD_API_RELEASE_TAG:-v2.0.0}
URL_PREFIX="https://github.com/${RELEASE_REPO}/releases/download/${RELEASE_TAG}"
INSTALL_DIR=${INSTALL_DIR:-/usr/local/bin}
CONFIG_DIR=${CONFIG_DIR:-/etc/wireguard-api}

case "$(uname -sm)" in
  "Darwin x86_64") FILENAME="wireguard-darwin-amd64" ;;
  "Darwin arm64") FILENAME="wireguard-darwin-arm64" ;;
  "Linux x86_64") FILENAME="wireguard-linux-amd64" ;;
  "Linux i686") FILENAME="wireguard-linux-386" ;;
  "Linux armv7l") FILENAME="wireguard-linux-arm" ;;
  "Linux aarch64") FILENAME="wireguard-linux-arm64" ;;
  *) echo "Unsupported architecture: $(uname -sm)" >&2; exit 1 ;;
esac

if [[ -n "${WIREGUARD_API_BINARY:-}" ]]; then
  if [[ ! -f "$WIREGUARD_API_BINARY" ]]; then
    echo "WIREGUARD_API_BINARY does not exist: $WIREGUARD_API_BINARY" >&2
    exit 1
  fi
  echo "Installing API binary from $WIREGUARD_API_BINARY"
  cp "$WIREGUARD_API_BINARY" "$INSTALL_DIR/wireguard"
else
  echo "Downloading $FILENAME from ${RELEASE_REPO} ${RELEASE_TAG}"
  if ! curl -sSLf "$URL_PREFIX/$FILENAME" -o "$INSTALL_DIR/wireguard"; then
    echo "Failed to download the V2 release; publish ${RELEASE_TAG} or set WIREGUARD_API_BINARY" >&2
    exit 1
  fi
fi

if ! chmod +x "$INSTALL_DIR/wireguard"; then
  echo "Failed to set executable permission on $INSTALL_DIR/wireguard" >&2
  exit 1
fi

# Install systemd service on Linux
if [[ "$(uname -s)" == "Linux" ]] && command -v systemctl &> /dev/null; then
  echo "Installing systemd service..."
  
  # Create config directory and .env file if it doesn't exist
  if [ ! -d "$CONFIG_DIR" ]; then
    mkdir -p "$CONFIG_DIR"
    echo "Created configuration directory: $CONFIG_DIR"
  fi
  
  # Check if .env file exists, create from .env.example if it doesn't
  if [ ! -f "$CONFIG_DIR/.env" ]; then
    echo "Creating .env file in $CONFIG_DIR"
    
    # Check if .env.example exists in current directory
    if [ -f "./.env.example" ]; then
      # Copy from .env.example to .env
      cp ./.env.example "$CONFIG_DIR/.env"
      echo "Copied from .env.example template"
    else
      # Create default .env file
      cat > "$CONFIG_DIR/.env" << 'EOF'
# Wireguard API Configuration
API_PORT=8080
AWG_PROFILE=awg2
EOF
      echo "Created default .env file"
    fi
    
    # Generate a random API token and add/replace it in .env file
    API_TOKEN=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32)
    if grep -q "^API_TOKEN=" "$CONFIG_DIR/.env"; then
      # Replace existing API_TOKEN line
      sed -i "s/^API_TOKEN=.*$/API_TOKEN=$API_TOKEN/" "$CONFIG_DIR/.env"
    else
      # Add API_TOKEN line if it doesn't exist
      echo "API_TOKEN=$API_TOKEN" >> "$CONFIG_DIR/.env"
    fi
    
    echo -e "\033[0;32mAPI Token generated: $API_TOKEN\033[0m"
    echo "Please save this token for API authentication"
  else
    echo "Using existing .env file in $CONFIG_DIR"
    
    # Check if API_TOKEN exists in .env, generate if it doesn't
    if ! grep -q "^API_TOKEN=" "$CONFIG_DIR/.env"; then
      API_TOKEN=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32)
      echo "API_TOKEN=$API_TOKEN" >> "$CONFIG_DIR/.env"
      echo -e "\033[0;32mAPI Token generated: $API_TOKEN\033[0m"
      echo "Please save this token for API authentication"
    else
      # Display existing API token
      API_TOKEN=$(grep "^API_TOKEN=" "$CONFIG_DIR/.env" | cut -d= -f2)
      echo -e "\033[0;32mExisting API Token: $API_TOKEN\033[0m"
    fi
  fi

  # Ensure API_PORT is explicit for the Go API and provisioning payloads.
  if ! grep -q "^API_PORT=" "$CONFIG_DIR/.env"; then
    echo "API_PORT=8080" >> "$CONFIG_DIR/.env"
  fi

  # Version 2 is AWG2-only by default. Existing explicit values are kept so
  # operators can use AWG_PROFILE=legacy for controlled compatibility tests.
  if ! grep -q "^AWG_PROFILE=" "$CONFIG_DIR/.env"; then
    echo "AWG_PROFILE=awg2" >> "$CONFIG_DIR/.env"
  fi
  
  # Copy wireguard.service file to systemd directory
  if [ -f "./wireguard.service" ]; then
    echo "Using existing wireguard.service file"
    
    # Copy service file to systemd directory
    if ! cp ./wireguard.service /etc/systemd/system/; then
      echo "Failed to copy service file to /etc/systemd/system/; try with sudo" >&2
      exit 1
    fi
  else
    echo "wireguard.service file not found in current directory"
    echo "Creating default service file..."
    
    # Create service file
    cat > /tmp/wireguard.service << 'EOF'
[Unit]
Description=Wireguard API Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/wireguard-api
ExecStart=/usr/local/bin/wireguard
EnvironmentFile=/etc/wireguard-api/.env
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    # Copy service file to systemd directory
    if ! cp /tmp/wireguard.service /etc/systemd/system/; then
      echo "Failed to copy service file to /etc/systemd/system/; try with sudo" >&2
      exit 1
    fi
  fi
  
  # Reload systemd, enable and start service
  systemctl daemon-reload
  systemctl enable wireguard.service
  systemctl start wireguard.service
  echo "Systemd service installed and started"
fi

# let's check if the service is running
if [[ "$(uname -s)" == "Linux" ]] && command -v systemctl &> /dev/null; then
  if ! systemctl is-active --quiet wireguard.service; then
    echo "Failed to start wireguard service" >&2
    echo "Check logs with: journalctl -u wireguard.service" >&2
    exit 1
  fi
fi

echo "wireguard-api V2 (AmneziaWG 2.0 profile) is successfully installed"

register_with_vipn_master() {
  if [[ ! -f "$CONFIG_DIR/.env" ]]; then
    return
  fi

  read -rp "Register this node with VIPN master? [Y/n]: " REGISTER_WITH_MASTER
  REGISTER_WITH_MASTER=${REGISTER_WITH_MASTER:-Y}
  if [[ ! ${REGISTER_WITH_MASTER} =~ ^[Yy]$ ]]; then
    echo "Skipping VIPN master registration. You can still add this server manually."
    return
  fi

  read -rp "Enter VIPN master API URL [https://api.vipn.io]: " MASTER_URL
  MASTER_URL=${MASTER_URL:-https://api.vipn.io}
  MASTER_URL=${MASTER_URL%/}

  read -rsp "Enter VIPN master provisioning token: " MASTER_TOKEN
  echo ""
  if [[ -z "$MASTER_TOKEN" ]]; then
    echo "VIPN master provisioning token is empty. Skipping registration."
    return
  fi

  API_PORT=$(grep "^API_PORT=" "$CONFIG_DIR/.env" | cut -d= -f2 || true)
  API_PORT=${API_PORT:-8080}
  API_TOKEN=$(grep "^API_TOKEN=" "$CONFIG_DIR/.env" | cut -d= -f2 || true)
  if [[ -z "$API_TOKEN" ]]; then
    echo "API_TOKEN not found in $CONFIG_DIR/.env. Skipping VIPN master registration."
    return
  fi

  PUBLIC_IP=$(curl -fsS --max-time 5 https://api.ipify.org || true)
  if [[ -z "$PUBLIC_IP" ]]; then
    PUBLIC_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
  fi
  if [[ -z "$PUBLIC_IP" ]]; then
    echo "Could not detect public IP. Skipping VIPN master registration."
    return
  fi

  VPN_TYPE="wireguard"
  if command -v awg &> /dev/null || [[ -f "/etc/amnezia/amneziawg/params" ]]; then
    VPN_TYPE="amneziawg"
  fi

  REGISTER_PAYLOAD=$(printf '{"ip":"%s","port":%s,"api_key":"%s","vpn_type":"%s"}' "$PUBLIC_IP" "$API_PORT" "$API_TOKEN" "$VPN_TYPE")

  echo "Registering this node with VIPN master..."
  if curl -fsS \
    -H "Authorization: Bearer $MASTER_TOKEN" \
    -H "Accept: application/json" \
    -H "Content-Type: application/json" \
    -d "$REGISTER_PAYLOAD" \
    "$MASTER_URL/master-api/register-node"; then
    echo ""
    echo -e "\033[0;32mVIPN master registration completed.\033[0m"
  else
    echo ""
    echo "VIPN master registration failed. You can still add this server manually using the API token below."
  fi
}

register_with_vipn_master

# Display API access information
if [[ -f "$CONFIG_DIR/.env" ]]; then
  API_PORT=$(grep "^API_PORT=" "$CONFIG_DIR/.env" | cut -d= -f2 || echo "8080")
  API_TOKEN=$(grep "^API_TOKEN=" "$CONFIG_DIR/.env" | cut -d= -f2)
  
  echo ""
  echo -e "\033[0;32mAPI Information:\033[0m"
  echo -e "- Service API: http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost"):$API_PORT"
  echo -e "- API Token: \033[0;33m$API_TOKEN\033[0m"
  echo -e "- Example usage: curl -H \"key: $API_TOKEN\" http://localhost:$API_PORT/api/wireguard-status"
fi
