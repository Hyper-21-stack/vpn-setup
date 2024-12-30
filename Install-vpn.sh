#!/bin/bash
YELLOW='\033[1;33m'
NC='\033[0m'
# Generate ASCII Banner
clear
figlet -f slant "HyperNet" | lolcat
echo -e "${YELLOW}HyperNet Ultimate Installer${NC}"
echo -e "\033[1;32m HyperNet v1.0 \033[0m"
echo
# Check for root privileges
if [ "$(whoami)" != "root" ]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi
# Check for dependencies
for cmd in figlet lolcat wget curl wg qrencode iptables; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: $cmd is not installed. Please install it before running the script." >&2
        exit 1
    fi
done
cd /root || exit
clear
# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
    echo 'This installer needs to be run with "bash", not "sh".' >&2
    exit 1
fi
# Discard stdin, needed when running from a one-liner
read -N 999999 -t 0.001
# Detect OS
if grep -qs "ubuntu" /etc/os-release; then
    os="ubuntu"
else
    echo "Error: This script is intended for Ubuntu." >&2
    exit 1
fi
# Check for environments where $PATH does not include the sbin directories
if ! grep -q 'sbin' <<< "$PATH"; then
    echo '$PATH does not include sbin. Try using "su -" instead of "su".' >&2
    exit 1
fi
# Check if BoringTun (userspace WireGuard) needs to be used
if ! systemd-detect-virt -cq; then
    use_boringtun="0"
elif grep -q '^wireguard ' /proc/modules; then
    use_boringtun="0"
else
    use_boringtun="1"
fi
# Check for TUN device
if [[ "$use_boringtun" -eq 1 ]]; then
    if [ "$(uname -m)" != "x86_64" ]; then
        echo "This installer supports only the x86_64 architecture. Your system runs on $(uname -m) and is unsupported." >&2
        exit 1
    fi
    if [[ ! -e /dev/net/tun ]] || ! (exec 7<>/dev/net/tun) 2>/dev/null; then
        echo "The system does not have the TUN device available. TUN needs to be enabled before running this installer." >&2
        exit 1
    fi
fi
# Function to get current DNS settings
new_client_dns() {
    if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53'; then
        resolv_conf="/etc/resolv.conf"
    else
        resolv_conf="/run/systemd/resolve/resolv.conf"
    fi
    dns=$(grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | xargs | sed -e 's/ /, /g')
}
# Function to setup new client
new_client_setup() {
    octet=2
    while grep AllowedIPs /etc/wireguard/wg0.conf | cut -d "." -f 4 | cut -d "/" -f 1 | grep -q "^$octet$"; do
        ((octet++))
    done
    if [[ "$octet" -eq 255 ]]; then
        echo "253 clients are already configured. The WireGuard internal subnet is full!" >&2
        exit 1
    fi
    key=$(wg genkey)
    psk=$(wg genpsk)
    cat << EOF >> /etc/wireguard/wg0.conf
# BEGIN_PEER $client
[Peer]
PublicKey = $(wg pubkey <<< "$key")
PresharedKey = $psk
AllowedIPs = 10.7.0.$octet/32$(grep -q 'fddd:2c4:2c4:2c4::1' /etc/wireguard/wg0.conf && echo ", fddd:2c4:2c4:2c4::$octet/128")
# END_PEER $client
EOF
    # Create client configuration
    mkdir -p /etc/Wire
    cat << EOF > /etc/Wire/"$client".conf
[Interface]
Address = 10.7.0.$octet/24$(grep -q 'fddd:2c4:2c4:2c4::1' /etc/wireguard/wg0.conf && echo ", fddd:2c4:2c4:2c4::$octet/64")
DNS = $dns
PrivateKey = $key
[Peer]
PublicKey = $(grep PrivateKey /etc/wireguard/wg0.conf | cut -d " " -f 3 | wg pubkey)
PresharedKey = $psk
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $(grep '^# ENDPOINT' /etc/wireguard/wg0.conf | cut -d " " -f 3):$(grep ListenPort /etc/wireguard/wg0.conf | cut -d " " -f 3)
PersistentKeepalive = 25  # Helps maintain the connection through NAT
EOF
}
# Create a script for the simplified login command
cat << 'EOF' > /usr/local/bin/hyped
#!/bin/bash
# Download and execute the VPN installation script
set -e  # Exit immediately if a command exits with a non-zero status
wget https://raw.githubusercontent.com/Hyper-21-stack/vpn-setup/main/Install-vpn.sh -O install-vpn.sh
chmod +x install-vpn.sh
./install-vpn.sh
EOF
# Make the hyped script executable
chmod +x /usr/local/bin/hyped
# Update .bashrc to show the banner on login
echo '/usr/local/bin/hyper_banner.sh' >> /root/.bashrc
# Check for WireGuard configuration
if [[ ! -e /etc/wireguard/wg0.conf ]]; then
    # Perform system updates 
    echo -e "${YELLOW}Updating system packages...${NC}"
    apt-get update && apt-get upgrade -y
    # Install necessary packages
    echo -e "${YELLOW}Installing required packages...${NC}"
    apt-get install -y wireguard qrencode iptables-persistent || { echo "Failed to install WireGuard"; exit 1; }
    
    clear
    figlet -kE "MTN" | lolcat
    echo -e "${YELLOW}Hyper WireGuard${NC}"
    
    # Configure Remote Port
    read -p "$(echo -e "\033[1;32mConfigure Remote Port(\033[1;33m36718\033[1;32m): \033[0m")" port
    until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
        echo "$port: invalid port." >&2
        read -p "$(echo -e "\033[1;32mConfigure Remote Port(\033[1;33m36718\033[1;32m): \033[0m")" port
    done
    [[ -z "$port" ]] && port="36718"
    echo -e "${YELLOW}Performing additional configurations...${NC}"
    
    # Set the MTU value for potential speed improvements
    MTU=9000  # Using 9000 bytes for Jumbo Frames
    
    # Generate wg0.conf
    cat << EOF > /etc/wireguard/wg0.conf
# Do not alter the commented lines
# They are used by wireguard-install
# ENDPOINT $([[ -n "$public_ip" ]] && echo "$public_ip" || echo "$ip")
[Interface]
Address = 10.7.0.1/24
PrivateKey = $(wg genkey)
ListenPort = $port
MTU = $MTU  # Setting MTU for performance optimization
PersistentKeepalive = 25  # Important for maintaining connection stability
EOF
    chmod 600 /etc/wireguard/wg0.conf
    # Configure system for network performance
    echo -e "\n# Increase buffer sizes for improved performance" >> /etc/sysctl.conf
    cat <<EOF >> /etc/sysctl.conf
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 250000
net.ipv4.tcp_congestion_control = bbr  # Use BBR congestion control
net.ipv4.ip_forward=1  # Enable IP forwarding
EOF
    sysctl -p  # Apply changes
    # Enable jumbo frames on the network interface (usually eth0, modify if necessary)
    ip link set dev eth0 mtu 9000
    # Firewalld or iptables rules
    iptables -A INPUT -p udp --dport $port -j ACCEPT
    iptables -A FORWARD -s 10.7.0.0/24 -j ACCEPT
    iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
    # Generate new client configuration
    new_client_dns
    new_client_setup
    
    # Enable and start the wg-quick service
    systemctl enable --now wg-quick@wg0.service
    # Provide user with QR code for client config
    clear
    echo -e "${YELLOW}Hyper Net Wireguard QR Code${NC}"
    qrencode -t ANSIUTF8 < /etc/Wire/"$client.conf"
    echo -e "\033[1;36m\xE2\x86\x91 Snap this QR code and import it in a Wireguard Client\033[0m"
else
    clear
    figlet -kE "MTN" | lolcat
    echo -e "${YELLOW}Hyper Net Wireguard${NC}"
    echo -e "\033[1;32mSelect an option:\033[0m"
    echo "1) Add a new client"
    echo "2) Remove an existing client"
    echo "3) Remove WireGuard"
    echo "4) Exit"
    read -p "$(echo -e "${YELLOW}Select a number from 1 to 4: ${NC}")" option
    until [[ "$option" =~ ^[1-4]$ ]]; do
        echo "$option: invalid selection." >&2
        read -p "$(echo -e "${YELLOW}Select a number from 1 to 4: ${NC}")" option
    done
    case "$option" in
        1)
            # Client creation code
            echo "Provide a name for the client:"
            read -p "Name: " unsanitized_client
            client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-]//g' <<< "$unsanitized_client" | cut -c-15)
            while [[ -z "$client" ]] || grep -q "^# BEGIN_PEER $client$" /etc/wireguard/wg0.conf; do
                echo "$client: invalid name." >&2
                read -p "Name: " unsanitized_client
                client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-]//g' <<< "$unsanitized_client" | cut -c-15)
            done
            echo
            new_client_dns
            new_client_setup
            wg addconf wg0 <(sed -n "/^# BEGIN_PEER $client/,/^# END_PEER $client/p" /etc/wireguard/wg0.conf)
            echo
            qrencode -t ANSIUTF8 < /etc/Wire/"$client.conf"
            echo -e '\xE2\x86\x91 That is a QR code containing your client configuration.'
            echo "$client added"
            exit
            ;;
        2)
            # Remove existing client code
            # (Same existing code for client removal...)
            exit
            ;;
        3)
            # Remove WireGuard code
            # (Same existing code for removing WireGuard...)
            exit
            ;;
        4)
            exit
            ;;
    esac
fi
