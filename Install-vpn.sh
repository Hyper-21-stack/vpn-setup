#!/bin/bash
YELLOW='\033[1;33m'
NC='\033[0m'
# Generate ASCII Banner
clear
figlet -f slant "HyperNet" | lolcat
echo -e "\033[1;33mHyperNet Ultimate Installer\033[0m"
echo -e "\033[1;32m HyperNet v1.0 \033[0m"
echo
# Check for root privileges
if [ "$(whoami)" != "root" ]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi
# Check for dependencies
for cmd in figlet lolcat wget curl wg qrencode; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: $cmd is not installed. Please install it before running the script." >&2
        exit 1
    fi
done
# Detect OS
if grep -qs "ubuntu" /etc/os-release; then
    os="ubuntu"
    os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
elif [[ -e /etc/debian_version ]]; then
    os="debian"
    os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
else
    echo "Error: This script is intended for Ubuntu or Debian." >&2
    exit 1
fi
if [[ "$os" == "ubuntu" && "$os_version" -lt 2204 ]]; then
    echo "Ubuntu 22.04 or higher is required to use this installer." >&2
    exit 1
fi
if [[ "$os" == "debian" && "$os_version" -lt 11 ]]; then
    echo "Debian 11 or higher is required to use this installer." >&2
    exit 1
fi
# Detect environments where $PATH does not include the sbin directories
if ! grep -q sbin <<< "$PATH"; then
    echo '$PATH does not include sbin. Try using "su -" instead of "su".' >&2
    exit 1
fi
# Detect if BoringTun (userspace WireGuard) needs to be used
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
        echo "This installer supports only the x86_64 architecture." >&2
        exit 1
    fi
    if [[ ! -e /dev/net/tun ]] || ! (exec 7<>/dev/net/tun) 2>/dev/null; then
        echo "The system does not have the TUN device available." >&2
        exit 1
    fi
fi
new_client_dns() {
    echo "Select a DNS server for the client:"
    echo "   1) Current system resolvers"
    echo "   2) Google"
    echo "   3) 1.1.1.1"
    echo "   4) OpenDNS"
    echo "   5) Quad9"
    echo "   6) AdGuard"
    read -p "DNS server [1]: " dns
    until [[ -z "$dns" || "$dns" =~ ^[1-6]$ ]]; do
        echo "$dns: invalid selection."
        read -p "DNS server [1]: " dns
    done
    
    case "$dns" in
        1|"")
            if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53' ; then
                resolv_conf="/etc/resolv.conf"
            else
                resolv_conf="/run/systemd/resolve/resolv.conf"
            fi
            dns=$(grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | xargs | sed -e 's/ /, /g')
        ;;
        2)
            dns="8.8.8.8, 8.8.4.4"
        ;;
        3)
            dns="1.1.1.1, 1.0.0.1"
        ;;
        4)
            dns="208.67.222.222, 208.67.220.220"
        ;;
        5)
            dns="9.9.9.9, 149.112.112.112"
        ;;
        6)
            dns="94.140.14.14, 94.140.15.15"
        ;;
    esac
}
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
install_wireguard() {
    if [[ ! -e /etc/wireguard/wg0.conf ]]; then
        echo "Installing WireGuard and its dependencies..."
        if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
            echo "Wget is required. Installing..."
            apt-get update
            apt-get install -y wget curl
        fi
        if [[ "$use_boringtun" -eq 0 ]]; then
            apt-get update
            apt-get install -y wireguard qrencode iptables
        else
            apt-get update
            apt-get install -y qrencode ca-certificates
            apt-get install -y wireguard-tools --no-install-recommends
            { wget -qO- https://wg.nyr.be/1/latest/download || curl -sL https://wg.nyr.be/1/latest/download; } | tar xz -C /usr/local/sbin/ --wildcards 'boringtun-*/boringtun' --strip-components 1
            mkdir /etc/systemd/system/wg-quick@wg0.service.d/ 2>/dev/null
            echo "[Service]
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=boringtun
Environment=WG_SUDO=1" > /etc/systemd/system/wg-quick@wg0.service.d/boringtun.conf
        fi
        echo "WireGuard has been successfully installed."
        
        # Generate wg0.conf
        cat << EOF > /etc/wireguard/wg0.conf
# Do not alter the commented lines
# They are used by wireguard-install
[Interface]
Address = 10.7.0.1/24
PrivateKey = $(wg genkey)
ListenPort = 36718
EOF
        chmod 600 /etc/wireguard/wg0.conf
        
        # Enable net.ipv4.ip_forward for the system
        echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wireguard-forward.conf
        echo 1 > /proc/sys/net/ipv4/ip_forward
        
        # If there's an IPv6 address, set it up as well
        if [[ -n "$ip6" ]]; then
            echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-wireguard-forward.conf
            echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
        fi
        
        echo "WireGuard installation and configuration complete!"
    else
        echo "WireGuard is already installed."
    fi
}
# Create a script for the simplified login command
cat << 'EOF' > /usr/local/bin/hyped
#!/bin/bash
# Download and execute the VPN installation script
set -e  
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
    install_wireguard
    
    new_client_dns
    default_client="Hyper"
    # Client setup and configuration goes here...
    new_client_setup
    # Enable and start the wg-quick service
    systemctl enable --now wg-quick@wg0.service
else
    clear
    figlet -kE "MTN" | lolcat
    echo -e "\033[1;33mHyper Net Wireguard\033[0m"
    echo -e "\033[1;32mSelect an option:\033[0m"
    echo "1) Add a new client"
    echo "2) Remove an existing client"
    echo "3) Remove WireGuard"
    echo "4) Exit"
    read -p "$(echo -e "\033[1;33mSelect a number from 1 to 4: \033[0m")" option
    until [[ "$option" =~ ^[1-4]$ ]]; do
        echo "$option: invalid selection." >&2
        read -p "$(echo -e "\033[1;33mSelect a number from 1 to 4: \033[0m")" option
    done
    case "$option" in
        1)
            echo "Provide a name for the client:"
            read -p "Name: " unsanitized_client
            client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-]//g' <<< "$unsanitized_client" | cut -c-15)
            while [[ -z "$client" ]] || grep -q "^# BEGIN_PEER $client$" /etc/wireguard/wg0.conf; do
                echo "$client: invalid name." >&2
                read -p "Name: " unsanitized_client
                client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]//g' <<< "$unsanitized_client" | cut -c-15)
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
            exit
            ;;
        3)
            read -p "$(echo -e "\033[1;31mUninstall Wireguard! [Y/N]: \033[0m")" remove
            until [[ "$remove" =~ ^[yYnN]*$ ]]; do
                echo "$remove: invalid selection." >&2
                read -p "$(echo -e "\033[1;33mUninstall Wireguard! [Y/N]: \033[0m")" remove
            done
            if [[ "$remove" =~ ^[yY]$ ]]; then
                port=$(grep '^ListenPort' /etc/wireguard/wg0.conf | cut -d " " -f 3)
                if systemctl is-active --quiet firewalld.service; then
                    ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.7.0.0/24 '"'"'!'"'"' -d 10.7.0.0/24' | grep -oE '[^ ]+$')
                    firewall-cmd --remove-port="$port"/udp
                    firewall-cmd --zone=trusted --remove-source=10.7.0.0/24
                    firewall-cmd --permanent --remove-port="$port"/udp
                    firewall-cmd --permanent --zone=trusted --remove-source=10.7.0.0/24
                    firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to "$ip"
                    firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to "$ip"
                else
                    systemctl disable --now wg-iptables.service
                    rm -rf /etc/systemd/system/wg-iptables.service
                fi
                systemctl disable --now wg-quick@wg0.service
                rm -rf /etc/systemd/system/wg-quick@wg0.service.d/boringtun.conf
                rm -rf /etc/sysctl.d/99-wireguard-forward.conf
                if [[ "$use_boringtun" -eq 0 ]]; then
                    rm -rf /etc/wireguard/
                    rm -rf /root/etc/Wire
                    apt-get remove --purge -y wireguard wireguard-tools
                else
                    { crontab -l 2>/dev/null | grep -v '/usr/local/sbin/boringtun-upgrade'; } | crontab -
                    rm -rf /etc/wireguard/
                    rm -rf /root/etc/Wire
                    apt-get remove --purge -y wireguard-tools
                    rm -rf /usr/local/sbin/boringtun /usr/local/sbin/boringtun-upgrade
                fi
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
