#!/bin/bash
# Define colors for output
YELLOW='\033[1;33m'
NC='\033[0m'
# Generate ASCII Banner
clear
figlet -f slant "HyperNet" | lolcat
echo -e "${YELLOW}HyperNet Ultimate Installer - Version 5${NC}"
# Check for root privileges
if [ "$(whoami)" != "root" ]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi
# Check for required dependencies
for cmd in figlet lolcat wget curl wg qrencode ca-certificates; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: $cmd is not installed. Installing it now..." >&2
        apt-get update
        apt-get install -y "$cmd" || { echo "Failed to install $cmd"; exit 1; }
    fi
done
# Set the working directory
cd /root || exit
clear
# Detect OS and ensure it's Ubuntu
if ! grep -qs "ubuntu" /etc/os-release; then
    echo "Error: This script is intended for Ubuntu." >&2
    exit 1
fi
# Check for TUN device
if [[ ! -e /dev/net/tun ]]; then
    echo "Error: The TUN device is not available." >&2
    exit 1
fi
# Configure MTU and Keepalive settings
MTU=9000  # Set MTU for jumbo frames
PERSISTENT_KEEPALIVE=25  # Helps maintain the connection alive through NAT
# Function to fetch DNS settings
get_dns() {
    local resolv_conf
    
    if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53'; then
        resolv_conf="/etc/resolv.conf"
    else
        resolv_conf="/run/systemd/resolve/resolv.conf"
    fi
    
    # Extract nameservers and provide them in the required format
    dns=$(grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | awk '{print $2}' | xargs | sed 's/ /, /g')
}
# Function to generate WireGuard server configuration
generate_wg_config() {
    cat << EOF > /etc/wireguard/wg0.conf
[Interface]
Address = 10.7.0.1/24
ListenPort = 51820
PrivateKey = $(wg genkey)
MTU = $MTU  # Setting MTU for performance optimization
PersistentKeepalive = $PERSISTENT_KEEPALIVE  # Keeps the connection alive through NAT
EOF
    chmod 600 /etc/wireguard/wg0.conf
}
# Check for existing WireGuard config
if [[ ! -e /etc/wireguard/wg0.conf ]]; then
    get_dns
    
    echo -e "${YELLOW}Setting up WireGuard...${NC}"
    generate_wg_config
    echo -e "${YELLOW}WireGuard configuration generated successfully!${NC}"
    # Enable IP forwarding
    echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wireguard-forward.conf
    sysctl -p
    # Configure the firewall rules (if using firewalld)
    if systemctl is-active --quiet firewalld.service; then
        firewall-cmd --add-port=51820/udp
        firewall-cmd --permanent --add-port=51820/udp
        firewall-cmd --reload
    fi
    echo -e "${YELLOW}WireGuard installation complete!${NC}"
else
    echo "The WireGuard configuration already exists. You may want to remove it before proceeding."
    exit 1
fi
# Function to add a new client
setup_client() {
    local client_id="$1"
    local client_key
    local client_psk
    # Generate key pairs
    client_key=$(wg genkey)
    client_psk=$(wg genpsk)
    # Update wg0.conf with new peer
    cat << EOF >> /etc/wireguard/wg0.conf
# BEGIN_PEER $client_id
[Peer]
PublicKey = $(wg pubkey <<< "$client_key")
PresharedKey = $client_psk
AllowedIPs = 10.7.0.$((octet++))/32  # Increase octet for each new client
# END_PEER $client_id
EOF
    # Create client configuration
    mkdir -p "/etc/Wire"
    cat << EOF > "/etc/Wire/$client_id.conf"
[Interface]
Address = 10.7.0.$((octet - 1))/24
PrivateKey = $client_key
[Peer]
PublicKey = $(grep "PrivateKey" /etc/wireguard/wg0.conf | awk '{print $3}')
Endpoint = $(hostname -I | awk '{print $1}'):51820
PersistentKeepalive = $PERSISTENT_KEEPALIVE  # Keep alive settings
EOF
    echo "$client_id has been added with configuration."
}
# Sample usage to add a new client
# Uncomment the following line for testing
# setup_client "client_name"
# Display instructions to the user
echo -e "${YELLOW}To add clients, call the setup_client function with the desired client name.${NC}"
