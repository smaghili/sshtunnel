#!/bin/bash

REPO_URL="https://github.com/smaghili/sshtunnel.git"
SCRIPT_PATH="/opt/sshtunnel"
SERVICE_NAME="vpn-tunnel.service"

# Default values
DEFAULT_TUN_NUMBER=9
DEFAULT_IP_LOCAL="192.168.85.2"
DEFAULT_IP_REMOTE="192.168.85.1"
DEFAULT_IP_MASK=30

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

# Function to uninstall VPN tunnel
uninstall_vpn() {
    echo "Uninstalling VPN tunnel..."
    
    # Stop and disable the service
    if systemctl is-active --quiet $SERVICE_NAME; then
        echo "Stopping VPN service..."
        sudo systemctl stop $SERVICE_NAME
        sudo systemctl disable $SERVICE_NAME
    fi
    
    # Remove the service file
    if [ -f "/etc/systemd/system/$SERVICE_NAME" ]; then
        echo "Removing service file..."
        sudo rm -f "/etc/systemd/system/$SERVICE_NAME"
        sudo systemctl daemon-reload
    fi
    
    # Remove sudoers file
    if [ -f "/etc/sudoers.d/vpn-tunnel" ]; then
        echo "Removing sudoers configuration..."
        sudo rm -f "/etc/sudoers.d/vpn-tunnel"
    fi
    
    # Get tunnel number and IPs from ssh.sh if it exists
    if [ -f "$SCRIPT_PATH/ssh.sh" ]; then
        TUN_NUMBER=$(grep "TUN_LOCAL=" "$SCRIPT_PATH/ssh.sh" | cut -d'=' -f2)
        REMOTE_IP=$(grep "HOST=" "$SCRIPT_PATH/ssh.sh" | cut -d'=' -f2)
        SSH_PORT=$(grep "HOST_PORT=" "$SCRIPT_PATH/ssh.sh" | cut -d'=' -f2)
    fi
    
    # Remove tunnel interface if it exists
    if [ ! -z "$TUN_NUMBER" ]; then
        echo "Removing tunnel interface..."
        sudo ip link del "tun$TUN_NUMBER" 2>/dev/null || true
    fi
    
    # Remove tunnel interface on remote server if possible
    if [ ! -z "$REMOTE_IP" ] && [ ! -z "$SSH_PORT" ]; then
        echo "Removing tunnel interface on remote server..."
        ssh -o StrictHostKeyChecking=no -p "$SSH_PORT" "root@$REMOTE_IP" "
            if [ ! -z \"$TUN_NUMBER\" ]; then
                ip link del tun$TUN_NUMBER 2>/dev/null || true
            fi
            # Remove main-Euro.sh and its crontab entry
            rm -f /root/main-Euro.sh
            crontab -l | grep -v '@reboot /root/main-Euro.sh' | crontab -
        " 2>/dev/null || true
    fi
    
    # Remove SSH key for the remote server
    if [ ! -z "$REMOTE_IP" ]; then
        echo "Removing SSH key for remote server..."
        ssh-keygen -R "$REMOTE_IP" 2>/dev/null || true
    fi
    
    # Remove script directory
    if [ -d "$SCRIPT_PATH" ]; then
        echo "Removing script directory..."
        sudo rm -rf "$SCRIPT_PATH"
    fi

    # Remove vpn-tunnel command
    sudo rm -f /usr/local/bin/vpn-tunnel

    echo "VPN tunnel uninstallation completed successfully!"
    exit 0
}

# Function to create vpn-tunnel command
create_vpn_command() {
    cat > /tmp/vpn-tunnel << 'EOL'
#!/bin/bash

SCRIPT_PATH="/opt/sshtunnel"
SERVICE_NAME="vpn-tunnel.service"

# Function to uninstall VPN tunnel
uninstall_vpn() {
    echo "Uninstalling VPN tunnel..."
    
    # Stop and disable the service
    if systemctl is-active --quiet $SERVICE_NAME; then
        echo "Stopping VPN service..."
        sudo systemctl stop $SERVICE_NAME
        sudo systemctl disable $SERVICE_NAME
    fi
    
    # Remove the service file
    if [ -f "/etc/systemd/system/$SERVICE_NAME" ]; then
        echo "Removing service file..."
        sudo rm -f "/etc/systemd/system/$SERVICE_NAME"
        sudo systemctl daemon-reload
    fi
    
    # Remove sudoers file
    if [ -f "/etc/sudoers.d/vpn-tunnel" ]; then
        echo "Removing sudoers configuration..."
        sudo rm -f "/etc/sudoers.d/vpn-tunnel"
    fi
    
    # Get tunnel number and IPs from ssh.sh if it exists
    if [ -f "$SCRIPT_PATH/ssh.sh" ]; then
        TUN_NUMBER=$(grep "TUN_LOCAL=" "$SCRIPT_PATH/ssh.sh" | cut -d'=' -f2)
        REMOTE_IP=$(grep "HOST=" "$SCRIPT_PATH/ssh.sh" | cut -d'=' -f2)
        SSH_PORT=$(grep "HOST_PORT=" "$SCRIPT_PATH/ssh.sh" | cut -d'=' -f2)
    fi
    
    # Remove tunnel interface if it exists
    if [ ! -z "$TUN_NUMBER" ]; then
        echo "Removing tunnel interface..."
        sudo ip link del "tun$TUN_NUMBER" 2>/dev/null || true
    fi
    
    # Remove tunnel interface on remote server if possible
    if [ ! -z "$REMOTE_IP" ] && [ ! -z "$SSH_PORT" ]; then
        echo "Removing tunnel interface on remote server..."
        ssh -o StrictHostKeyChecking=no -p "$SSH_PORT" "root@$REMOTE_IP" "
            if [ ! -z \"$TUN_NUMBER\" ]; then
                ip link del tun$TUN_NUMBER 2>/dev/null || true
            fi
            # Remove main-Euro.sh and its crontab entry
            rm -f /root/main-Euro.sh
            crontab -l | grep -v '@reboot /root/main-Euro.sh' | crontab -
        " 2>/dev/null || true
    fi
    
    # Remove SSH key for the remote server
    if [ ! -z "$REMOTE_IP" ]; then
        echo "Removing SSH key for remote server..."
        ssh-keygen -R "$REMOTE_IP" 2>/dev/null || true
    fi
    
    # Remove script directory
    if [ -d "$SCRIPT_PATH" ]; then
        echo "Removing script directory..."
        sudo rm -rf "$SCRIPT_PATH"
    fi

    # Remove vpn-tunnel command
    sudo rm -f /usr/local/bin/vpn-tunnel

    echo "VPN tunnel uninstallation completed successfully!"
}

# Help function
show_help() {
    echo "Usage: vpn-tunnel [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  install    Install VPN tunnel"
    echo "  uninstall  Remove VPN tunnel completely"
    echo "  status     Show VPN tunnel status"
    echo "  help       Show this help message"
}

# Main script logic
case "$1" in
    "uninstall")
        uninstall_vpn
        ;;
    "status")
        systemctl status $SERVICE_NAME
        ;;
    "help")
        show_help
        ;;
    *)
        echo "Unknown command. Use 'vpn-tunnel help' for usage information."
        exit 1
        ;;
esac
EOL

    sudo mv /tmp/vpn-tunnel /usr/local/bin/
    sudo chmod +x /usr/local/bin/vpn-tunnel
}

# Function to clone or update the Git repository
gitClone() {
    sudo mkdir -p "$SCRIPT_PATH"
    if [ ! -d "$SCRIPT_PATH/.git" ]; then
        sudo git clone "$REPO_URL" "$SCRIPT_PATH" || { echo "Failed to clone repository"; exit 1; }
    else
        # Force reset any local changes and pull
        (cd "$SCRIPT_PATH" && \
         sudo git fetch origin && \
         sudo git reset --hard origin/main && \
         sudo git clean -fd) || { echo "Failed to update repository"; exit 1; }
    fi
    echo "Git repository cloned or updated successfully."
}

# Function to get next IP address
get_next_ip() {
    local ip=$1
    local prefix=$(echo $ip | cut -d. -f1-3)
    local last_octet=$(echo $ip | cut -d. -f4)
    local next_octet=$((last_octet + 1))
    echo "${prefix}.${next_octet}"
}

# Function to check if tunnel or IP exists on remote server
check_tunnel_and_ip() {
    local tunnel_num=$1
    local remote_ip=$2
    local exists_tunnel=false
    local exists_ip=false
    
    if ssh -o StrictHostKeyChecking=no -p "$SSH_PORT" "root@$FOREIGN_IP" "ip link show tun$tunnel_num" >/dev/null 2>&1; then
        exists_tunnel=true
    fi
    
    if ssh -o StrictHostKeyChecking=no -p "$SSH_PORT" "root@$FOREIGN_IP" "ip addr | grep -q '$remote_ip'"; then
        exists_ip=true
    fi
    
    echo "$exists_tunnel $exists_ip"
}

# Function to get tunnel number with validation
get_tunnel_number() {
    local tunnel_number
    while true; do
        read -p "Enter tunnel number (default: $DEFAULT_TUN_NUMBER): " TUN_INPUT
        tunnel_number=${TUN_INPUT:-$DEFAULT_TUN_NUMBER}
        
        if ! [[ "$tunnel_number" =~ ^[0-9]+$ ]]; then
            echo "Please enter a valid number"
            continue
        fi
        
        if ssh -o StrictHostKeyChecking=no -p "$SSH_PORT" "root@$FOREIGN_IP" "ip link show tun$tunnel_number" >/dev/null 2>&1; then
            echo "Tunnel number $tunnel_number already exists on the remote server."
            read -p "Do you want to replace it? (y/n): " replace
            if [[ $replace =~ ^[Yy]$ ]]; then
                ssh -o StrictHostKeyChecking=no -p "$SSH_PORT" "root@$FOREIGN_IP" "ip link del tun$tunnel_number" 2>/dev/null || true
                break
            fi
        else
            break
        fi
    done
    TUNNEL_NUMBER="$tunnel_number"
}

# Function to get remote IP with validation
get_remote_ip() {
    local temp_ip
    while true; do
        read -p "Enter remote IP (default: $DEFAULT_IP_REMOTE): " IP_REMOTE_INPUT
        temp_ip=${IP_REMOTE_INPUT:-$DEFAULT_IP_REMOTE}
        
        if ! [[ "$temp_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "Please enter a valid IP address"
            continue
        fi
        
        if ssh -o StrictHostKeyChecking=no -p "$SSH_PORT" "root@$FOREIGN_IP" "ip addr | grep -q '$temp_ip'"; then
            echo "Remote IP $temp_ip already exists on the remote server."
            read -p "Do you want to replace it? (y/n): " replace
            if [[ $replace =~ ^[Yy]$ ]]; then
                echo "Removing existing tunnel with IP $temp_ip..."
                ssh -o StrictHostKeyChecking=no -p "$SSH_PORT" "root@$FOREIGN_IP" "
                    for iface in \$(ip addr show | grep '$temp_ip' | awk '{print \$NF}'); do
                        ip link del \$iface 2>/dev/null || true
                    done
                "
                break
            fi
        else
            break
        fi
    done
    REMOTE_IP="$temp_ip"
}

# Modified installation type selection function
select_installation_type() {
    echo "Please select installation type:"
    echo "1) Easy Install (Default Settings)"
    echo "2) Custom Install"
    read -p "Enter your choice (1 or 2): " INSTALL_TYPE
    
    case $INSTALL_TYPE in
        1)
            echo "Easy installation selected..."
            TUN_NUMBER=$DEFAULT_TUN_NUMBER
            IP_REMOTE=$DEFAULT_IP_REMOTE
            ;;
        2)
            echo "Custom installation selected..."
            get_tunnel_number
            TUN_NUMBER=$TUNNEL_NUMBER
            get_remote_ip
            IP_REMOTE=$REMOTE_IP
            ;;
        *)
            echo "Invalid option. Using easy installation..."
            TUN_NUMBER=$DEFAULT_TUN_NUMBER
            IP_REMOTE=$DEFAULT_IP_REMOTE
            ;;
    esac
    
    IP_LOCAL=$(get_next_ip "$IP_REMOTE")
    echo "Local IP will be set to: $IP_LOCAL"
    IP_MASK=$DEFAULT_IP_MASK
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

    if [ ! -f ~/.ssh/id_rsa ]; then
        ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N "" -q
        check_command "Failed to generate SSH key"
    fi

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
        interface="eth0"
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
        "
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
        "
    fi
    
    check_command "Failed to update sshd_config on $server"
}

# Function to create systemd service
create_systemd_service() {
    for script in ssh.sh iran-route.sh; do
        if [ -f "$SCRIPT_PATH/$script" ]; then
            sudo chmod +x "$SCRIPT_PATH/$script"
        else
            echo "Warning: $script not found in the repository."
        fi
    done

    if systemctl is-active --quiet vpn-tunnel.service; then
        sudo systemctl stop vpn-tunnel.service
        sudo systemctl disable vpn-tunnel.service
    fi
    sudo rm -f /etc/systemd/system/vpn-tunnel.service

    sudo tee /etc/systemd/system/vpn-tunnel.service > /dev/null << EOL
[Unit]
Description=VPN Tunnel Service with Monitor
After=network.target

[Service]
ExecStart=/bin/bash $SCRIPT_PATH/ssh.sh
Restart=on-failure
RestartSec=30
StartLimitInterval=360
StartLimitBurst=5
User=root
WorkingDirectory=$SCRIPT_PATH
SyslogIdentifier=vpn-tunnel

[Install]
WantedBy=multi-user.target
EOL

    check_command "Failed to create vpn-tunnel.service"
    echo "Created vpn-tunnel.service successfully."

    echo "root ALL=(ALL) NOPASSWD: $SCRIPT_PATH/ssh.sh" | sudo tee /etc/sudoers.d/vpn-tunnel > /dev/null
    sudo chmod 0440 /etc/sudoers.d/vpn-tunnel
}

# Function to create ssh.sh with custom values
create_ssh_script() {
    cat > "$SCRIPT_PATH/ssh.sh" << EOL
#!/bin/bash

set -e

HOST=$FOREIGN_IP
HOST_PORT=$SSH_PORT
TUN_LOCAL=$TUN_NUMBER
TUN_REMOTE=$TUN_NUMBER
IP_LOCAL=$IP_LOCAL
IP_REMOTE=$IP_REMOTE
IP_MASK=$IP_MASK

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
    ssh -o StrictHostKeyChecking=no -p "\$HOST_PORT" "root@\$HOST" "ip link del tun\$TUN_REMOTE" || true
    sudo ip link del tun\$TUN_LOCAL 2>/dev/null || true
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

    ip route add 0.0.0.0/1 via \$IP_REMOTE || true
    ip route add 128.0.0.0/1 via \$IP_REMOTE || true

    LOCAL_INTERFACE=\$(ip route | grep default | awk '{print \$5}' | head -n1)

    iptables -t nat -A POSTROUTING -o \$LOCAL_INTERFACE -j MASQUERADE || true
    iptables -t nat -A POSTROUTING -o tun\$TUN_LOCAL -j MASQUERADE || true

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
    sleep 30
done
EOL

    sudo chmod +x "$SCRIPT_PATH/ssh.sh"
}

setup_foreign_server() {
    echo "Configuring foreign server..."
    ssh -o StrictHostKeyChecking=no -p "$SSH_PORT" "root@$FOREIGN_IP" "
        cat > main-Euro.sh << EOL
#!/bin/bash

iptables -F || true
iptables -t nat -F || true

iptables -t nat -A POSTROUTING -o $FOREIGN_INTERFACE -j MASQUERADE || true
EOL

        chmod +x main-Euro.sh
        ./main-Euro.sh
    " || { echo "Failed to configure foreign server"; exit 1; }
    
    echo "Foreign server configured successfully."
    echo "Setting up crontab on foreign server..."
    ssh -o StrictHostKeyChecking=no -p "$SSH_PORT" "root@$FOREIGN_IP" "
        (crontab -l 2>/dev/null; echo '@reboot /root/main-Euro.sh') | crontab -
    " || { echo "Failed to set up crontab on foreign server"; exit 1; }
    echo "Crontab setup on foreign server completed successfully."
}

# Main script execution starts here
case "$1" in
    "uninstall")
        uninstall_vpn
        ;;
    *)
        echo "Starting VPN tunnel setup for Ubuntu..."

        # Clone or update the repository
        gitClone

        # First get server details before anything else
        read -p "Enter the IP address of the foreign server: " FOREIGN_IP
        read -p "Enter the SSH port of the foreign server: " SSH_PORT

        # Setup SSH keys
        echo "Setting up SSH keys..."
        setup_ssh_keys "root@$FOREIGN_IP" "$SSH_PORT"

        # Now select installation type after we have FOREIGN_IP and SSH_PORT
        select_installation_type

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

        # Create ssh.sh with custom values
        create_ssh_script

        # Setup foreign server
        setup_foreign_server

        # Create systemd service
        create_systemd_service

        # Create vpn-tunnel command
        create_vpn_command

        # Enable and start the VPN service
        echo "Enabling and starting VPN service..."
        sudo systemctl daemon-reload
        sudo systemctl enable vpn-tunnel.service
        sudo systemctl start vpn-tunnel.service

# Check if the service started successfully
        if ! sudo systemctl is-active --quiet vpn-tunnel.service; then
            echo -e "\n\033[1;31m✗ Error: VPN service did not start properly.\033[0m"
            echo -e "Please check the logs with: \033[1mjournalctl -u vpn-tunnel.service\033[0m\n"
            exit 1
        fi

        # If we get here, everything was successful
        clear  # Clear the screen for final message
        
        # Print fancy completion banner
        echo -e "\n\033[1;32m╔════════════════════════════════════════╗"
        echo -e "║                                            ║"
        echo -e "║      ✓ VPN Tunnel Setup Completed!        ║"
        echo -e "║                                            ║"
        echo -e "╚════════════════════════════════════════╝\033[0m\n"

        # Print usage guide with nice formatting
        echo -e "\033[1;34m┌─ Usage Guide ────────────────────────────┐\033[0m"
        echo -e "\033[1;37m  Command:\033[0m vpn-tunnel [COMMAND]\n"
        
        echo -e "\033[1;34m┌─ Available Commands ──────────────────────┐\033[0m"
        echo -e "  \033[1;33minstall\033[0m     │  Install VPN tunnel"
        echo -e "  \033[1;33muninstall\033[0m   │  Remove VPN tunnel completely"
        echo -e "  \033[1;33mstatus\033[0m      │  Show VPN tunnel status"
        echo -e "  \033[1;33mhelp\033[0m        │  Show this help message"
        echo -e "\033[1;34m└─────────────────────────────────────────┘\033[0m\n"

        # Print quick start tip
        echo -e "\033[1;32m┌─ Quick Start ──────────────────────────┐\033[0m"
        echo -e "  Check VPN status: \033[1mvpn-tunnel status\033[0m"
        echo -e "\033[1;32m└────────────────────────────────────────┘\033[0m\n"
        ;;
esac
