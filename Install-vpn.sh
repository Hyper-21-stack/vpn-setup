#!/bin/bash
# Color definitions
YELLOW='\033[1;33m'
NC='\033[0m'
LOGFILE="/var/log/hypernet_installer.log"
# Logging function
log() {
    echo "$(date +"%Y-%m-%d %H:%M:%S") - $1" >> "$LOGFILE"
}
# Function to display the banner
display_banner() {
    clear
    echo -e "${YELLOW}==============================${NC}"
    figlet -f slant "HyperNet" | lolcat
    echo -e "${YELLOW}HyperNet Ultimate Installer${NC}"
    echo -e "${YELLOW}HyperNet v1.5${NC}"
    echo -e "${YELLOW}==============================${NC}"
    echo
}
# Function to stop blinking text while loading
stop_blinking() {
    echo -e "\033[?25l" # Hide the cursor
}
# Function to show the client QR code
show_client_qr_code() {
    client=$1  # Client name passed as an argument
    qrencode -t ANSIUTF8 < /etc/Wire/"${client}.conf"
    echo -e "${YELLOW}\xE2\x86\x91 Snap this QR code and Import it in a Wireguard Client${NC}"
}
# Generate ASCII Banner
display_banner
stop_blinking
# Check for root privileges
if [ "$(whoami)" != "root" ]; then
    echo "Error: This script must be run as root." >&2
    log "Error: Script not run as root."
    exit 1
fi
# Check for dependencies
required_cmds=(figlet lolcat wget curl wg qrencode)
for cmd in "${required_cmds[@]}"; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: $cmd is not installed. Please install it before running the script." >&2
        log "Error: $cmd is not installed."
        exit 1
    fi
done
cd /root || exit
display_banner
# Detect OS
if grep -qs "ubuntu" /etc/os-release; then
    os="ubuntu"
else
    echo "Error: This script is intended for Ubuntu." >&2
    log "Error: Unsupported OS detected."
    exit 1
fi
# Check for TUN device
if [[ ! -e /dev/net/tun ]]; then
    echo "TUN device is not available." >&2
    log "Error: TUN device not available."
    exit 1
fi
# Function to get DNS servers
new_client_dns() {
    if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53'; then
        resolv_conf="/etc/resolv.conf"
    else
        resolv_conf="/run/systemd/resolve/resolv.conf"
    fi
    dns=$(grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | xargs | sed -e 's/ /, /g')
}
# Function to setup a new client configuration
new_client_setup() {
    octet=2
    while grep -q "AllowedIPs = 10.7.0.$octet/32" /etc/wireguard/wg0.conf; do
        ((octet++))
    done
    if [[ "$octet" -eq 255 ]]; then
        echo "253 clients are already configured. The WireGuard internal subnet is full!" >&2
        log "Error: Maximum number of clients reached."
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
    mkdir -p /etc/Wire
    cat << EOF > /etc/Wire/"$client".conf
[Interface]
Address = 10.7.0.$octet/24$(grep -q 'fddd:2c4:2c4:2c4::1' /etc/wireguard/wg0.conf && echo ", fddd:2c4:2c4:2c4::$octet/64")
DNS = $dns
PrivateKey = $key
[Peer]
PublicKey = $(grep 'PrivateKey' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | wg pubkey)
PresharedKey = $psk
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $(grep '^# ENDPOINT' /etc/wireguard/wg0.conf | cut -d ' ' -f 3):$(grep 'ListenPort' /etc/wireguard/wg0.conf | cut -d ' ' -f 3)
PersistentKeepalive = 25
EOF
}
# Main script logic
if [[ ! -e /etc/wireguard/wg0.conf ]]; then
    # Check for wget and curl
    for cmd in wget curl; do
        if ! command -v "$cmd" &> /dev/null; then
            echo "Error: $cmd is required to use this installer." >&2
            read -n1 -r -p "Press any key to install wget and continue..."
            apt-get update
            apt-get install -y wget curl
        fi
    done
    
    clear
    display_banner
    echo -e "${YELLOW}Hyper WireGuard${NC}"
    
    # IP Address Handling
    new_client_dns  # Get DNS information
    default_client="Hyper"
    client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]//g' <<< "$default_client" | cut -c-15)
    new_client_setup  # Set up the client
    # QR Code Generation
    echo -e "${YELLOW}Clients configuration completed. QR code will be displayed.${NC}"
    qrencode -t ANSIUTF8 < /etc/Wire/"$client.conf"
    echo -e "${YELLOW}\xE2\x86\x91 Snap this QR code and Import it in a Wireguard Client${NC}"
else
    clear
    display_banner
    echo -e "${YELLOW}Hyper Net Wireguard${NC}"
    echo -e "${YELLOW}Select an option:${NC}"
    # Interactive menu for managing clients
    echo "1) Add a new client"
    echo "2) Remove an existing client"
    echo "3) Remove WireGuard"
    echo "4) Show client QR code"
    echo "5) Exit"
    read -p "$(echo -e "${YELLOW}Select a number from 1 to 5: ${NC}")" option
    until [[ "$option" =~ ^[1-5]$ ]]; do
        echo "$option: invalid selection." >&2
        read -p "$(echo -e "${YELLOW}Select a number from 1 to 5: ${NC}")" option
    done
    case "$option" in
        1)
            echo "Provide a name for the client:"
            read -p "Name: " unsanitized_client
            client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-]//g' <<< "$unsanitized_client" | cut -c-15)
            
            while [[ -z "$client" ]] || grep -q "^# BEGIN_PEER $client$" /etc/wireguard/wg0.conf; do
                echo "$client: invalid name." >&2
                read -p "Name: " unsanitized_client
                client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-]/_/g' <<< "$unsanitized_client" | cut -c-15)
            done
            echo
            new_client_dns
            new_client_setup
            wg addconf wg0 <(sed -n "/^# BEGIN_PEER $client/,/^# END_PEER $client/p" /etc/wireguard/wg0.conf)
            echo "$client added!"
            qrencode -t ANSIUTF8 < /etc/Wire/"$client.conf"
            echo -e "${YELLOW}\xE2\x86\x91 That is a QR code containing your client configuration.${NC}"
            ;;
        2)
            number_of_clients=$(grep -c '^# BEGIN_PEER' /etc/wireguard/wg0.conf)
            if [[ "$number_of_clients" == 0 ]]; then
                echo "There are no existing clients!" >&2
                exit 1
            fi
            echo "Select the client to remove:"
            grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | nl -s ') '
            read -p "Client: " client_number
            until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
                echo "$client_number: invalid selection." >&2
                read -p "Client: " client_number
            done
            client=$(grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | sed -n "$client_number"p)
            echo
            read -p "Confirm $client removal? [y/N]: " remove
            until [[ "$remove" =~ ^[yYnN]*$ ]]; do
                echo "$remove: invalid selection." >&2
                read -p "Confirm $client removal? [y/N]: " remove
            done
            if [[ "$remove" =~ ^[yY]$ ]]; then
                wg set wg0 peer "$(sed -n "/^# BEGIN_PEER $client$/,\$p" /etc/wireguard/wg0.conf | grep -m 1 PublicKey | cut -d " " -f 3)" remove
                sed -i "/^# BEGIN_PEER $client$/,/^# END_PEER $client$/d" /etc/wireguard/wg0.conf
                echo "$client removed!"
            else
                echo "$client removal aborted!"
            fi
            ;;
        3)
            read -p "$(echo -e "${YELLOW}Uninstall Wireguard! [Y/N]: ${NC}")" remove
            until [[ "$remove" =~ ^[yYnN]*$ ]]; do
                echo "$remove: invalid selection." >&2
                read -p "$(echo -e "${YELLOW}Uninstall Wireguard! [Y/N]: ${NC}")" remove
            done
            if [[ "$remove" =~ ^[yY]$ ]]; then
                port=$(grep '^ListenPort' /etc/wireguard/wg0.conf | cut -d " " -f 3)
                if systemctl is-active --quiet firewalld.service; then
                    ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.7.0.0/24 '"'"'!'"'"' -d 10.7.0.0/24' | grep -oE '[^ ]+$')
                    firewall-cmd --remove-port="$port"/udp
                    firewall-cmd --zone=trusted --remove-source=10.7.0.0/24
                    firewall-cmd --permanent --remove-port="$port"/udp
                    firewall-cmd --permanent --zone=trusted --remove-source=10.7.0.0/24
                else
                    systemctl disable --now wg-iptables.service
                    rm -rf /etc/systemd/system/wg-iptables.service
                fi
                systemctl disable --now wg-quick@wg0.service
                rm -rf /etc/systemd/system/wg-quick@wg0.service.d/boringtun.conf
                rm -rf /etc/sysctl.d/99-wireguard-forward.conf
                rm -rf /etc/wireguard/
                rm -rf /root/etc/Wire
                apt-get remove --purge -y wireguard wireguard-tools
                echo "WireGuard removed!"
            else
                echo "WireGuard removal aborted!"
            fi
            exit
            ;;
        4)
            number_of_clients=$(grep -c '^# BEGIN_PEER' /etc/wireguard/wg0.conf)
            if [[ "$number_of_clients" == 0 ]]; then
                echo "There are no existing clients!" >&2
                exit 1
            fi
            echo "Select the client to show QR code:"
            grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | nl -s ') '
            read -p "Client: " client_number
            until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
                echo "$client_number: invalid selection." >&2
                read -p "Client: " client_number
            done
            client=$(grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | sed -n "$client_number"p)
            # Constructing the expected file path for the client configuration
            client_conf_file="/etc/Wire/${client}.conf"
            if [ -f "$client_conf_file" ]; then
                show_client_qr_code "$client"
            else
                echo "Error: Client config for '$client' not found." >&2
            fi
            ;;
        5)
            exit
            ;;
    esac
fi
