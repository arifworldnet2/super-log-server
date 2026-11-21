#!/usr/bin/env bash
# ==============================================================================
# Super LOG Server - Automated Installer for CentOS 7 (x86_64)
# ==============================================================================
set -e

echo "=========================================================="
echo "  Super LOG Server - CentOS 7 Auto Installer"
echo "=========================================================="

if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root!"
  exit 1
fi

# Step 1: Fix CentOS 7 EOL Repositories (Point to vault.centos.org 7.9.2009)
echo "[1/7] Configuring CentOS 7 Vault repositories..."
sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*.repo 2>/dev/null || true
sed -i 's/mirrorlist.centos.org/vault.centos.org/g' /etc/yum.repos.d/*.repo 2>/dev/null || true
sed -i 's/#baseurl=http:\/\/mirror.centos.org/baseurl=http:\/\/vault.centos.org/g' /etc/yum.repos.d/CentOS-*.repo 2>/dev/null || true
sed -i 's/#\s*baseurl=http:\/\/vault/baseurl=http:\/\/vault/g' /etc/yum.repos.d/*.repo 2>/dev/null || true
sed -i 's/mirror.centos.org/vault.centos.org/g' /etc/yum.repos.d/*.repo 2>/dev/null || true
sed -i 's/vault.centos.org\/centos\/$releasever/vault.centos.org\/7.9.2009/g' /etc/yum.repos.d/*.repo 2>/dev/null || true
sed -i 's/vault.centos.org\/$releasever/vault.centos.org\/7.9.2009/g' /etc/yum.repos.d/*.repo 2>/dev/null || true
sed -i 's/$releasever/7.9.2009/g' /etc/yum.repos.d/CentOS-*.repo 2>/dev/null || true

yum clean all || true

# Step 2: Install EPEL and Build Dependencies
echo "[2/7] Installing dependencies & development tools..."
yum install -y epel-release || true

# Fix archived EPEL repositories
sed -i 's|^metalink=|#metalink=|g' /etc/yum.repos.d/epel*.repo 2>/dev/null || true
sed -i 's|^#baseurl=http://download.fedoraproject.org/pub/epel/|baseurl=https://archives.fedoraproject.org/pub/archive/epel/|g' /etc/yum.repos.d/epel*.repo 2>/dev/null || true
sed -i 's|^baseurl=http://download.fedoraproject.org/pub/epel/|baseurl=https://archives.fedoraproject.org/pub/archive/epel/|g' /etc/yum.repos.d/epel*.repo 2>/dev/null || true
sed -i 's/mirrorlist.centos.org/vault.centos.org/g' /etc/yum.repos.d/*.repo 2>/dev/null || true
sed -i 's/mirror.centos.org/vault.centos.org/g' /etc/yum.repos.d/*.repo 2>/dev/null || true
sed -i 's/$releasever/7.9.2009/g' /etc/yum.repos.d/CentOS-*.repo 2>/dev/null || true

yum clean all || true
yum groupinstall -y "Development Tools"
yum install -y openssl11 openssl11-devel libffi-devel bzip2-devel wget sqlite-devel zlib-devel git curl net-tools firewalld ca-certificates

# Step 3: Check or Compile Python 3.10 with OpenSSL 1.1
echo "[3/7] Setting up Python 3.10..."
if ! command -v python3.10 &> /dev/null; then
    echo "[*] Compiling Python 3.10.14 with OpenSSL 1.1..."
    
    # Setup OpenSSL 1.1 unified layout
    mkdir -p /usr/local/openssl11
    [ ! -e /usr/local/openssl11/lib ] && ln -sf /usr/lib64/openssl11 /usr/local/openssl11/lib
    [ ! -e /usr/local/openssl11/include ] && ln -sf /usr/include/openssl11 /usr/local/openssl11/include

    cd /usr/src
    if command -v curl &> /dev/null; then
        curl -fkSL https://www.python.org/ftp/python/3.10.14/Python-3.10.14.tgz -o Python-3.10.14.tgz
    else
        wget --no-check-certificate -q https://www.python.org/ftp/python/3.10.14/Python-3.10.14.tgz
    fi
    tar xzf Python-3.10.14.tgz
    cd Python-3.10.14
    export CFLAGS=$(pkg-config --cflags openssl11 2>/dev/null || echo "-I/usr/include/openssl11")
    export LDFLAGS=$(pkg-config --libs openssl11 2>/dev/null || echo "-L/usr/lib64/openssl11 -lssl -lcrypto")
    ./configure --prefix=/usr/local --with-openssl=/usr/local/openssl11
    make altinstall -j$(nproc)
    
    ln -sf /usr/local/bin/python3.10 /usr/bin/python3.10
    ln -sf /usr/local/bin/pip3.10 /usr/bin/pip3.10
    
    cd /
    rm -rf /usr/src/Python-3.10.14*
fi

python3.10 --version

# Step 4: Setup Project Directory
echo "[4/7] Deploying Super LOG Server..."
INSTALL_DIR="/opt/super-log-server"
if [ -d "$INSTALL_DIR/.git" ]; then
    echo "[*] Updating existing repository..."
    cd "$INSTALL_DIR"
    git pull origin main
else
    echo "[*] Cloning repository..."
    rm -rf "$INSTALL_DIR"
    git clone https://github.com/arifworldnet2/super-log-server.git "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

# Step 5: Setup Virtual Environment & Install Packages
echo "[5/7] Installing Python dependencies..."
python3.10 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

# Step 6: Configure Systemd Service
echo "[6/7] Creating systemd service..."
cat << 'EOF' > /etc/systemd/system/superlog.service
[Unit]
Description=Super LOG - MikroTik Syslog & Traffic Monitoring Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/super-log-server
ExecStart=/opt/super-log-server/venv/bin/python server.py
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable superlog.service
systemctl restart superlog.service

# Step 7: Open Firewall Ports
echo "[7/7] Configuring firewall..."
if systemctl is-active --quiet firewalld; then
    firewall-cmd --permanent --add-port=8000/tcp || true
    firewall-cmd --permanent --add-port=5514/udp || true
    firewall-cmd --reload || true
fi

SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -z "$SERVER_IP" ] && SERVER_IP="<server-ip>"

echo ""
echo "=========================================================="
echo "  [SUCCESS] Super LOG Server Installed & Started!"
echo "=========================================================="
echo "  Web UI URL    : http://${SERVER_IP}:8000"
echo "  Syslog Port   : UDP 5514"
echo "  Service Status: systemctl status superlog"
echo "  Service Logs  : journalctl -u superlog -f"
echo "=========================================================="
