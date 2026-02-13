#!/usr/bin/env bash
# install.sh - Install ospfd (RFC 2328 OSPF v2 routing daemon)
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { printf "${GREEN}[INFO]${NC}  %s\n" "$*"; }
warn()  { printf "${YELLOW}[WARN]${NC}  %s\n" "$*"; }
err()   { printf "${RED}[ERROR]${NC} %s\n" "$*" >&2; }

if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root (try: sudo ./install.sh)"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WHEEL=$(find "$SCRIPT_DIR" -name 'ospfd-*.whl' -print -quit)
VENV_DIR="/opt/ospfd"

if [[ -z "$WHEEL" ]]; then
    err "No .whl file found in $SCRIPT_DIR"
    exit 1
fi

# -- Ensure python3-venv is available -----------------------------------------
if ! python3 -m venv --help &>/dev/null; then
    info "Installing python3-venv ..."
    apt-get install -y python3-venv
fi

# -- Create virtual environment ------------------------------------------------
info "Creating virtual environment at $VENV_DIR ..."
python3 -m venv --clear "$VENV_DIR"

# -- Install the wheel into the venv ------------------------------------------
info "Installing $WHEEL ..."
"$VENV_DIR/bin/pip" install --force-reinstall "$WHEEL"

# -- Symlink the binary to /usr/local/sbin ------------------------------------
ln -sf "$VENV_DIR/bin/ospfd" /usr/local/sbin/ospfd
info "ospfd linked at /usr/local/sbin/ospfd"

# -- Deploy configuration ------------------------------------------------------
if [[ -f /etc/ospfd/ospfd.yaml ]]; then
    warn "/etc/ospfd/ospfd.yaml already exists — not overwriting"
    info "New default config saved to /etc/ospfd/ospfd.yaml.dist"
    mkdir -p /etc/ospfd
    cp "${SCRIPT_DIR}/ospfd.yaml" /etc/ospfd/ospfd.yaml.dist
else
    info "Installing configuration to /etc/ospfd/ospfd.yaml ..."
    mkdir -p /etc/ospfd
    cp "${SCRIPT_DIR}/ospfd.yaml" /etc/ospfd/ospfd.yaml
fi
chmod 644 /etc/ospfd/ospfd.yaml*

# -- Deploy systemd unit -------------------------------------------------------
info "Installing systemd service ..."
cp "${SCRIPT_DIR}/ospfd.service" /etc/systemd/system/ospfd.service
chmod 644 /etc/systemd/system/ospfd.service
systemctl daemon-reload

# -- Summary -------------------------------------------------------------------
printf "\n"
info "Installation complete!"
printf "\n"
printf "  Next steps:\n"
printf "  1. Edit the config:\n"
printf "       sudo vi /etc/ospfd/ospfd.yaml\n"
printf "     Set router_id and interface/area settings for your network.\n"
printf "\n"
printf "  2. Start the service:\n"
printf "       sudo systemctl enable --now ospfd\n"
printf "\n"
printf "  3. Check status:\n"
printf "       sudo systemctl status ospfd\n"
printf "       journalctl -u ospfd -f\n"
printf "\n"
