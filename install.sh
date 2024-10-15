#!/bin/bash

REPO_URL="https://github.com/smaghili/sshtunnel.git"
SCRIPT_PATH="/opt/sshtunnel"

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install a package
install_package() {
    if command_exists apt-get; then
        sudo apt-get update >/dev/null 2>&1
        sudo apt-get install -y "$1" >/dev/null 2>&1
    else
        echo "Error: apt-get not found. Please install $1 manually."
        exit 1
    fi
}

# Function to clone or update the Git repository
gitClone() {
    sudo mkdir -p "$SCRIPT_PATH"
    if [ ! -d "$SCRIPT_PATH/.git" ]; then
        sudo git clone "$REPO_URL" "$SCRIPT_PATH" || { echo "Failed to clone repository"; exit 1; }
    else
        (cd "$SCRIPT_PATH" && sudo git pull) || { echo "Failed to update repository"; exit 1; }
    fi
    echo "Git repository cloned or updated successfully."
}

# Function to check if a command was successful
check_command() {
    if [ $? -ne 0 ]; then
        echo "Warning: $1"
    fi
}

# Function to setup SSH keys
setup_ssh_keys() {
    local remote_server=$1
    local ssh_port=$2

    # Generate SSH key if it doesn't exist
    if [ ! -f ~/.ssh/id_rsa ]; then
        ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N "" -q
        check_command "Failed to generate SSH key"
    fi

    # Copy the public key to the remote server
    ssh-copy-id -p $ssh_port $remote_server
    check_command "Failed to copy SSH key to remote server"

    echo "SSH keys setup completed."
}

# Function to get the main network interface
get_main_interface() {
    local server=$1
    
    if [ "$server" = "localhost" ]; then
        interface=$(ip route | grep default | awk '{print $5}' | head -n1)
    else
        interface=$(ssh -o StrictHostKeyChecking=no -p "$SSH_PORT" "$server" "ip route | grep default | awk '{print \$5}' | head -n1")
    fi
    
    if [ -z "$interface" ]; then
        echo "Warning: Could not determine the main network interface on $server"
        interface="eth0"  # Fallback to a default interface
    fi
    echo "$interface"
}

# Function to update EURO_IP in iran-route.sh
update_iran_route() {
    local ip=$1
    if [ ! -f "$SCRIPT_PATH/iran-route.sh" ]; then
        echo "Warning: iran-route.sh file not found in $SCRIPT_PATH."
        return
    fi
    sed -i "1s/EURO_IP=.*/EURO_IP=$ip/" "$SCRIPT_PATH/iran-route.sh" >/dev/null 2>&1
    check_command "Failed to update EURO_IP in iran-route.sh"
    echo "Updated EURO_IP in iran-route.sh to $ip"
}

# Function to update sysctl.conf without duplicates
update_sysctl_conf() {
    local server=$1
    
    sysctl_config="
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv6.conf.all.forwarding = 1
net.ipv4.tcp_window_scaling = 1
net.core.rmem_max = 26214400
net.core.rmem_default = 26214400
net.core.wmem_max = 26214400
net.core.wmem_default = 26214400
net.core.netdev_max_backlog = 2048
"
    
    if [ "$server" = "localhost" ]; then
        echo "$sysctl_config" | while IFS= read -r line; do
            if ! grep -qF "$line" /etc/sysctl.conf; then
                echo "$line" | sudo tee -a /etc/sysctl.conf >/dev/null 2>&1
            fi
        done
    else
        echo "$sysctl_config" | ssh -o StrictHostKeyChecking=no -p "$SSH_PORT" "$server" "
            while IFS= read -r line; do
                if ! grep -qF \"\$line\" /etc/sysctl.conf; then
                    echo \"\$line\" | sudo tee -a /etc/sysctl.conf >/dev/null 2>&1
                fi
            done
        " >/dev/null 2>&1
    fi
    
    check_command "Failed to update sysctl.conf on $server"
}

# Function to update sshd_config without duplicates
update_sshd_config() {
    local server=$1
    
    if [ "$server" = "localhost" ]; then
        if ! grep -qF 'PermitTunnel yes' /etc/ssh/sshd_config; then
            echo 'PermitTunnel yes' | sudo tee -a /etc/ssh/sshd_config >/dev/null 2>&1
        fi
        sudo sysctl -p >/dev/null 2>&1
        sudo systemctl restart ssh >/dev/null 2>&1
    else
        ssh -o StrictHostKeyChecking=no -p "$SSH_PORT" "$server" "
            if ! grep -qF 'PermitTunnel yes' /etc/ssh/sshd_config; then
                echo 'PermitTunnel yes' | sudo tee -a /etc/ssh/sshd_config >/dev/null 2>&1
            fi
            sudo sysctl -p >/dev/null 2>&1
            sudo systemctl restart ssh >/dev/null 2>&1
        " >/dev/null 2>&1
    fi
    
    check_command "Failed to update sshd_config on $server"
}

# Function to create systemd service
create_systemd_service() {
    # Ensure ssh.sh and iran-route.sh are executable
    for script in ssh.sh iran-route.sh; do
        if [ -f "$SCRIPT_PATH/$script" ]; then
            sudo chmod +x "$SCRIPT_PATH/$script"
        else
            echo "Warning: $script not found in the repository."
        fi
    done

    # Disable and remove old service if exists
    if systemctl is-active --quiet vpn-tunnel.service; then
        sudo systemctl stop vpn-tunnel.service
        sudo systemctl disable vpn-tunnel.service
    fi
    sudo rm -f /etc/systemd/system/vpn-tunnel.service

    # Create new service file
    sudo tee /etc/systemd/system/vpn-tunnel.service > /dev/null << EOL
[Unit]
Description=VPN Tunnel Service with Monitor
After=network.target

[Service]
ExecStart=/bin/bash $SCRIPT_PATH/ssh.sh
Restart=on-failure
RestartSec=1
User=root
WorkingDirectory=$SCRIPT_PATH
SyslogIdentifier=vpn-tunnel

[Install]
WantedBy=multi-user.target
EOL

    check_command "Failed to create vpn-tunnel.service"
    echo "Created vpn-tunnel.service successfully."

    # Add sudoers rule to allow running the script without password
    echo "root ALL=(ALL) NOPASSWD: $SCRIPT_PATH/ssh.sh" | sudo tee /etc/sudoers.d/vpn-tunnel > /dev/null
    sudo chmod 0440 /etc/sudoers.d/vpn-tunnel
}

# Main script execution
echo "Starting VPN tunnel setup for Ubuntu..."

# Clone or update the repository
gitClone

# Get user input
read -p "Enter the IP address of the foreign server: " FOREIGN_IP
read -p "Enter the SSH port of the foreign server: " SSH_PORT

# Setup SSH keys
echo "Setting up SSH keys..."
setup_ssh_keys "root@$FOREIGN_IP" "$SSH_PORT"

# Update EURO_IP in iran-route.sh
update_iran_route "$FOREIGN_IP"

# Get main network interfaces
LOCAL_INTERFACE=$(get_main_interface "localhost")
FOREIGN_INTERFACE=$(get_main_interface "root@$FOREIGN_IP")

# Update sysctl.conf and sshd_config on both servers
echo "Updating system configurations..."
update_sysctl_conf "localhost"
update_sysctl_conf "root@$FOREIGN_IP"
update_sshd_config "localhost"
update_sshd_config "root@$FOREIGN_IP"
echo "System configurations updated successfully."

# Create ssh.sh
cat > "$SCRIPT_PATH/ssh.sh" << EOL
#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status.

HOST=$FOREIGN_IP
HOST_PORT=$SSH_PORT
TUN_LOCAL=9
TUN_REMOTE=9 
IP_LOCAL=192.168.85.2 
IP_REMOTE=192.168.85.1 
IP_MASK=30 

EXPECTED_IP="$FOREIGN_IP"
SCRIPT_PATH="$SCRIPT_PATH"

# Function to check if a specific route exists
check_route() {
    if ip route | grep -q "2.144.0.0"; then
        return 0
    else
        return 1
    fi
}

setup_vpn() {
    echo "Setting up VPN tunnel..."
    ssh -o StrictHostKeyChecking=no -p "$SSH_PORT" "root@$FOREIGN_IP" "ip link del tun9" || true
    sudo ip link del tun9 2>/dev/null || true
    modprobe tun || true
    ssh -o StrictHostKeyChecking=no -w \${TUN_LOCAL}:\${TUN_REMOTE} -f \${HOST} -p \${HOST_PORT} "
      ip addr add \${IP_REMOTE}/\${IP_MASK} dev tun\${TUN_REMOTE} 2>/dev/null || true
      ip link set tun\${TUN_REMOTE} up || true
      true"
    sleep 3

    ip addr add \${IP_LOCAL}/\${IP_MASK} dev tun\${TUN_LOCAL} 2>/dev/null || true
    ip link set tun\${TUN_LOCAL} up || true
    echo "VPN tunnel setup completed."

    if ! check_route; then
        if [ -f "\$SCRIPT_PATH/iran-route.sh" ]; then
            echo "Configuring routes..."
            "\$SCRIPT_PATH/iran-route.sh"
            echo "Routes configured."
        else
            echo "Warning: iran-route.sh not found in \$SCRIPT_PATH"
        fi
    else
        echo "Route 2.144.0.0 already exists. Skipping iran-route.sh execution."
    fi

    echo "Applying firewall rules..."
    iptables -F || true
    iptables -t nat -F || true

    ip route add \$EXPECTED_IP via \$(ip route | awk '/default/ {print \$3}') metric 1 || true

    ip route add 0.0.0.0/1 via 192.168.85.1 || true
    ip route add 128.0.0.0/1 via 192.168.85.1 || true

    LOCAL_INTERFACE=\$(ip route | grep default | awk '{print \$5}' | head -n1)

    iptables -t nat -A POSTROUTING -o \$LOCAL_INTERFACE -j MASQUERADE || true
    iptables -t nat -A POSTROUTING -o tun9 -j MASQUERADE || true

    echo "Firewall rules applied."
    echo "VPN setup process completed."
}

check_vpn() {
    CURRENT_IP=\$(curl -s ipconfig.io)
    if [ "\$CURRENT_IP" != "\$EXPECTED_IP" ]; then
        echo "VPN check failed. Current IP: \$CURRENT_IP, Expected IP: \$EXPECTED_IP"
        return 1
    fi
    return 0
}

# Main loop
while true; do
    if ! check_vpn; then
        echo "VPN disconnected. Restarting immediately..."
        setup_vpn
    fi
    sleep 30  # Minimal delay to prevent excessive CPU usage
done
EOL

sudo chmod +x "$SCRIPT_PATH/ssh.sh"

# Create systemd service
create_systemd_service

# Enable and start the VPN service
echo "Enabling and starting VPN service..."
sudo systemctl daemon-reload
sudo systemctl enable vpn-tunnel.service
sudo systemctl start vpn-tunnel.service

# Check if the service started successfully
if ! sudo systemctl is-active --quiet vpn-tunnel.service; then
    echo "Warning: VPN service may not have started properly. Please check the logs with 'journalctl -u vpn-tunnel.service'"
else
    echo "VPN service started successfully."
fi

echo "VPN tunnel setup completed!"
echo "The VPN service is now configured to start automatically on boot and will be monitored continuously."
echo "You can check the status of the service with: sudo systemctl status vpn-tunnel.service"
