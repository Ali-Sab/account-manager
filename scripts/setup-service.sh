#!/bin/bash
set -e

# ═══════════════════════════════════════════════════════════════════════════
# Account Manager — Start Service
# Starts the systemd unit for this service (prod by default).
# The unit must already exist — run setup-pi.sh first.
#
# Usage:
#   bash scripts/setup-service.sh          # starts account-manager-prod
#   bash scripts/setup-service.sh dev      # starts account-manager-dev
# ═══════════════════════════════════════════════════════════════════════════

ENV="${1:-prod}"
SERVICE="account-manager-${ENV}"

if [[ $EUID -ne 0 ]]; then
  exec sudo bash "$0" "$@"
fi

if ! systemctl list-unit-files "${SERVICE}.service" &>/dev/null; then
  echo "Unit ${SERVICE}.service not found. Run setup-pi.sh first."
  exit 1
fi

if systemctl is-active --quiet "$SERVICE"; then
  echo "Restarting ${SERVICE}..."
  systemctl restart "$SERVICE"
else
  echo "Starting ${SERVICE}..."
  systemctl start "$SERVICE"
fi

sleep 2

if systemctl is-active --quiet "$SERVICE"; then
  echo "[✓] ${SERVICE} is running"
  echo ""
  echo "  Status:  sudo systemctl status ${SERVICE}"
  echo "  Logs:    sudo journalctl -u ${SERVICE} -f"
  echo "  Stop:    sudo systemctl stop ${SERVICE}"
else
  echo "[✗] ${SERVICE} failed to start. Last 20 log lines:"
  echo ""
  journalctl -u "$SERVICE" -n 20 --no-pager
  exit 1
fi
