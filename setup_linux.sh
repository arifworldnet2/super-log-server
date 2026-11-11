#!/bin/bash
# ==============================================================
# Super LOG - Automated Deployment Script for Ubuntu / Debian
# ==============================================================

set -e

echo "[1/6] Updating system packages..."
sudo apt update && sudo apt upgrade -y

echo "[2/6] Installing Python 3, venv, Nginx, Git, UFW..."
sudo apt install -y python3 python3-pip python3-venv nginx ufw git

echo "[3/6] Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "[4/6] Initializing Database..."
python3 -c "import database; database.init_db(); print('Database tables verified!')"

echo "[5/6] Configuring Firewall (UFW)..."
sudo ufw allow 22/tcp comment 'SSH'
sudo ufw allow 80/tcp comment 'HTTP Web'
sudo ufw allow 443/tcp comment 'HTTPS Web'
sudo ufw allow 5514/udp comment 'MikroTik Syslog UDP'
sudo ufw --force enable

echo "[6/6] Setting up Systemd Service..."
if [ -f "superlog.service" ]; then
    CURRENT_DIR=$(pwd)
    sed -i "s|/opt/superlog|$CURRENT_DIR|g" superlog.service
    sudo cp superlog.service /etc/systemd/system/superlog.service
    sudo systemctl daemon-reload
    sudo systemctl enable superlog.service
    sudo systemctl restart superlog.service
    echo "Super LOG Service started successfully!"
fi

echo "=============================================================="
echo " Super LOG is now running!"
echo " Check status with: sudo systemctl status superlog"
echo " View live logs: sudo journalctl -u superlog -f"
echo "=============================================================="
