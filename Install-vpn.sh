#!/bin/bash
# Color definitions
YELLOW='\033[1;33m'
NC='\033[0m'
# Log file for installation
LOGFILE="/var/log/hypernet_installer.log"
# Utility function for logging
log() {
    echo "$(date +"%Y-%m-%d %H:%M:%S") - $1" >> "$LOGFILE"
}
# Generate ASCII Banner
clear
figlet -f slant "HyperNet" | lolcat
echo -e "${YELLOW}HyperNet Ultimate Installer${NC}"
echo -e "${YELLOW}HyperNet v1.5${NC}"
echo
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
clear
# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
    echo 'This installer needs to be run with "bash", not "sh".' >&2
    log "Error: Script not run with bash."
    exit 1
fi
# Discard stdin when running from a one-liner
read -N 999999 -t 0.001
# Detect OS
if grep -qs "ubuntu" /etc/os-release; then
    os="ubuntu"
else
    echo "Error: This script is intended for Ubuntu." >&2
    log "Error: Unsupported OS detected."
    exit 1
fi
# Detect environments where $PATH does not include the sbin directories
if ! grep -q 'sbin' <<< "$PATH"; then
    echo '$PATH does not include sbin. Try using "su -" instead of "su".' >&2
    log "Error: $PATH does not include sbin."
    exit 1
fi
# Detect if BoringTun needs to be used
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
        echo "This installer supports only the x86_64 architecture. Your system is $(uname -m) and is unsupported." >&2
        log "Error: Unsupported architecture detected."
        exit 1
    fi
    if [[ ! -e /dev/net/tun ]] || ! (exec 7<>/dev/net/tun) 2>/dev/null; then
        echo "The system does not have the TUN device available. TUN needs to be enabled before running this installer." >&2
        log "Error: TUN device not available."
        exit 1
    fi
fi
# Function to get DNS servers
new_client_dns() {
    # Locate resolv.conf
    if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53'; then
        resolv_conf="/etc/resolv.conf"
    else
        resolv_conf="/run/systemd/resolve/resolv.conf"
    fi
    # Extract nameservers in required format
    dns=$(grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | xargs | sed -e 's/ /, /g')
}
# Function to setup a new client configuration
new_client_setup() {
    octet=2
    while grep AllowedIPs /etc/wireguard/wg0.conf | cut -d "." -f 4 | cut -d "/" -f 1 | grep -q "^$octet$"; do
        ((octet++))
    done
    if [[ "$octet" -eq 255 ]]; then
        echo "253 clients are already configured. The WireGuard internal subnet is full!" >&2
        log "Error: Maximum number of clients reached."
        exit 1
    fi
    key=$(wg genkey)
    psk=$(wg genpsk)
    # Append Peer configuration to wg0.conf
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
PersistentKeepalive = 25
EOF
}
# Function to create login command script
create_hyped_script() {
    # Create the hyped command
    cat << 'EOF' > /usr/local/bin/hyped
#!/bin/bash
# Download and execute the VPN installation script
set -e
wget -q --show-progress https://raw.githubusercontent.com/Hyper-21-stack/vpn-setup/main/Install-vpn.sh -O install-vpn.sh
chmod +x install-vpn.sh
./install-vpn.sh
EOF
    chmod +x /usr/local/bin/hyped
}
# Update .bashrc to show the banner on login
echo '/usr/local/bin/hyper_banner.sh' >> /root/.bashrc
# Check for WireGuard configuration
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
    figlet -kE "MTN" | lolcat
    echo -e "${YELLOW}Hyper WireGuard${NC}"
    
    # IPv4 Address Handling
    if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
        ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
    else
        number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
        echo
        echo "Which IPv4 address should be used?"
        ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
        read -p "IPv4 address [1]: " ip_number
        until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
            echo "$ip_number: invalid selection." >&2
            read -p "IPv4 address [1]: " ip_number
        done
        [[ -z "$ip_number" ]] && ip_number="1"
        ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
    fi
    # IPv6 Address Handling
    if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
        ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
    elif [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
        number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
        echo
        echo "Which IPv6 address should be used?"
        ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
        read -p "IPv6 address [1]: " ip6_number
        until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
            echo "$ip6_number: invalid selection." >&2
            read -p "IPv6 address [1]: " ip6_number
        done
        [[ -z "$ip6_number" ]] && ip6_number="1"
        ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
    fi
    # Port Configuration
    read -p "$(echo -e "${YELLOW}Configure Remote Port(${YELLOW}36718${YELLOW}): ${NC}")" port
    until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
        echo "$port: invalid port." >&2
        read -p "$(echo -e "${YELLOW}Configure Remote Port(${YELLOW}36718${YELLOW}): ${NC}")" port
    done
    [[ -z "$port" ]] && port="36718"
    echo -e "${YELLOW}Performing system updates and upgrades...${NC}"
    
    default_client="Hyper"
    client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]//g' <<< "$default_client" | cut -c-15)
    [[ -z "$client" ]] && client="client"
    new_client_dns
    
    MTU=9000  # Set MTU for potential speed improvements
    # Automatic updates for BoringTun
    if [[ "$use_boringtun" -eq 1 ]]; then
        echo
        echo "BoringTun will be installed to set up WireGuard in the system."
        read -p "Should automatic updates be enabled for it? [Y/n]: " boringtun_updates
        until [[ "$boringtun_updates" =~ ^[yYnN]*$ ]]; do
            echo "$remove: invalid selection."
            read -p "Should automatic updates be enabled for it? [Y/n]: " boringtun_updates
        done
        [[ -z "$boringtun_updates" ]] && boringtun_updates="y"
    fi
    # Install WireGuard and associated packages
    if [[ "$use_boringtun" -eq 0 ]]; then
        apt-get update
        apt-get install -y wireguard qrencode
    else
        apt-get update
        apt-get install -y qrencode ca-certificates wireguard-tools --no-install-recommends
        wget -qO- https://wg.nyr.be/1/latest/download | tar xz -C /usr/local/sbin/ --wildcards 'boringtun-*/boringtun' --strip-components 1
        mkdir -p /etc/systemd/system/wg-quick@wg0.service.d/
        echo "[Service]
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=boringtun
Environment=WG_SUDO=1" > /etc/systemd/system/wg-quick@wg0.service.d/boringtun.conf
    fi
    # Setup WireGuard configuration
    cat << EOF > /etc/wireguard/wg0.conf
# Do not alter the commented lines
# They are used by wireguard-install
# ENDPOINT $([[ -n "$public_ip" ]] && echo "$public_ip" || echo "$ip")
[Interface]
Address = 10.7.0.1/24$([[ -n "$ip6" ]] && echo ", fddd:2c4:2c4:2c4::1/64")
PrivateKey = $(wg genkey)
ListenPort = $port
MTU = $MTU
PersistentKeepalive = 25
EOF
    chmod 600 /etc/wireguard/wg0.conf
    
    # Configure system for network performance
    echo -e "\n# Increase buffer sizes for improved performance" >> /etc/sysctl.conf
    echo -e "net.core.rmem_max = 16777216\nnet.core.wmem_max = 16777216" >> /etc/sysctl.conf
    sysctl -p 
    # Enable IP forwarding
    echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wireguard-forward.conf
    echo 1 > /proc/sys/net/ipv4/ip_forward
    if [[ -n "$ip6" ]]; then
        echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-wireguard-forward.conf
        echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
    fi
    # Firewalld rules if using firewalld
    if systemctl is-active --quiet firewalld.service; then
        firewall-cmd --add-port="$port"/udp --permanent
        firewall-cmd --zone=trusted --add-source=10.7.0.0/24 --permanent
    else
        iptables_path=$(command -v iptables)
        echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to $ip
ExecStart=$iptables_path -I INPUT -p udp --dport $port -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s 10.7.0.0/24 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to $ip
ExecStop=$iptables_path -D INPUT -p udp --dport $port -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s 10.7.0.0/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" > /etc/systemd/system/wg-iptables.service
        systemctl enable --now wg-iptables.service
    fi
    # Generate the custom client configuration
    new_client_setup
    # Enable and start the wg-quick service
    systemctl enable --now wg-quick@wg0.service
    # Set up automatic updates for BoringTun if the user wanted to
    if [[ "$boringtun_updates" =~ ^[yY]$ ]]; then
        cat << 'EOF' > /usr/local/sbin/boringtun-upgrade
#!/bin/bash
latest=$(wget -qO- https://wg.nyr.be/1/latest 2>/dev/null || curl -sL https://wg.nyr.be/1/latest 2>/dev/null)
if ! head -1 <<< "$latest" | grep -qiE "^boringtun.+[0-9]+\.[0-9]+.*$"; then
    echo "Update server unavailable"
    exit
fi
current=$(/usr/local/sbin/boringtun -V)
if [[ "$current" != "$latest" ]]; then
    download="https://wg.nyr.be/1/latest/download"
    xdir=$(mktemp -d)
    if { wget -qO- "$download" 2>/dev/null || curl -sL "$download"; } | tar xz -C "$xdir" --wildcards "boringtun-*/boringtun" --strip-components 1; then
        systemctl stop wg-quick@wg0.service
        rm -f /usr/local/sbin/boringtun
        mv "$xdir"/boringtun /usr/local/sbin/boringtun
        systemctl start wg-quick@wg0.service
        echo "Successfully updated to $(/usr/local/sbin/boringtun -V)"
    else
        echo "boringtun update failed"
    fi
    rm -rf "$xdir"
else
    echo "$current is up to date"
fi
EOF
        chmod +x /usr/local/sbin/boringtun-upgrade
        { crontab -l 2>/dev/null; echo "$(( $RANDOM % 60 )) $(( $RANDOM % 3 + 3 )) * * * /usr/local/sbin/boringtun-upgrade &>/dev/null"; } | crontab -
    fi
    # Generate QR Code for client configuration
    clear
    figlet -kE "MTN" | lolcat
    echo -e "${YELLOW}Hyper Net Wireguard QR Code${NC}"
    echo
    qrencode -t ANSIUTF8 < /etc/Wire/"$client.conf"
    echo
    echo -e "${YELLOW}\xE2\x86\x91Snap this QR code and Import it in a Wireguard Client${NC}"
else
    clear
    figlet -kE "MTN" | lolcat
    echo -e "${YELLOW}Hyper Net Wireguard${NC}"
    echo -e "${YELLOW}Select an option:${NC}"
    # Interactive menu for managing clients
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
            echo
            qrencode -t ANSIUTF8 < /etc/Wire/"$client.conf"
            echo -e '\xE2\x86\x91 That is a QR code containing your client configuration.'
            echo "$client added"
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
            exit
            ;;
    esac
fi
