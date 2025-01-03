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
for cmd in figlet lolcat wget curl wg qrencode openssl stunnel4; do
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
# Discard stdin. Needed when running from a one-liner which includes a newline
read -N 999999 -t 0.001
# Detect OS
if grep -qs "ubuntu" /etc/os-release; then
    os="ubuntu"
else
    echo "Error: This script is intended for Ubuntu." >&2
    exit 1
fi
# Detect environments where $PATH does not include the sbin directories
if ! grep -q 'sbin' <<< "$PATH"; then
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
        echo "This installer supports only the x86_64 architecture. Your system runs on $(uname -m) and is unsupported." >&2
        exit 1
    fi
    if [[ ! -e /dev/net/tun ]] || ! (exec 7<>/dev/net/tun) 2>/dev/null; then
        echo "The system does not have the TUN device available. TUN needs to be enabled before running this installer." >&2
        exit 1
    fi
fi
new_client_dns() {
    # Locate the proper resolv.conf
    if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53'; then
        resolv_conf="/etc/resolv.conf"
    else
        resolv_conf="/run/systemd/resolve/resolv.conf"
    fi
    # Extract nameservers and provide them in the required format
    dns=$(grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | xargs | sed -e 's/ /, /g')
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
# Change endpoint to use obfuscation port (443)
Endpoint = $(grep '^# ENDPOINT' /etc/wireguard/wg0.conf | cut -d " " -f 3):443
PersistentKeepalive = 25
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
    clear
    figlet -kE "MTN" | lolcat
    echo -e "\033[1;33mHyper WireGuard\033[0m"
    # Install stunnel
    apt-get update
    apt-get install -y stunnel4
    # Configure stunnel
    cat << EOF > /etc/stunnel/stunnel.conf
pid = /var/run/stunnel.pid
setuid = stunnel4
setgid = stunnel4
daemon = yes
[wireguard]
accept = 443
connect = 127.0.0.1:51820
EOF
    # Create a self-signed certificate for stunnel
    openssl req -new -x509 -days 365 -nodes -newkey rsa:2048 \
      -keyout /etc/stunnel/stunnel.pem \
      -out /etc/stunnel/stunnel.pem \
      -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=localhost"
    # Set permissions for the stunnel certificate
    chmod 600 /etc/stunnel/stunnel.pem
    # Enable and start stunnel service
    systemctl enable stunnel4
    systemctl start stunnel4
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
    
    read -p "$(echo -e "\033[1;32mConfigure Remote Port(443): \033[0m")" port
    until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
        echo "$port: invalid port." >&2
        read -p "$(echo -e "\033[1;32mConfigure Remote Port(443): \033[0m")" port
    done
    [[ -z "$port" ]] && port="443"
    echo -e "\033[1;33mPerforming system updates and upgrades...\033[0m"
    
    default_client="Hyper"
    client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]//g' <<< "$default_client" | cut -c-15)
    [[ -z "$client" ]] && client="client"
    new_client_dns
    
    # Generate wg0.conf
    cat << EOF > /etc/wireguard/wg0.conf
# Do not alter the commented lines
# They are used by wireguard-install
# ENDPOINT ${ip}:$port
[Interface]
Address = 10.7.0.1/24$([[ -n "$ip6" ]] && echo ", fddd:2c4:2c4:2c4::1/64")
PrivateKey = $(wg genkey)
ListenPort = 51820  # WireGuard's internal port
EOF
    chmod 600 /etc/wireguard/wg0.conf
    # Enable and start the wg-quick service
    systemctl enable --now wg-quick@wg0.service
    
    # Generate the custom client configuration
    new_client_setup
    
    # Firewalld rules
    if systemctl is-active --quiet firewalld.service; then
        firewall-cmd --add-port="$port"/tcp
        firewall-cmd --zone=trusted --add-source=10.7.0.0/24
        firewall-cmd --permanent --add-port="$port"/tcp
        firewall-cmd --permanent --zone=trusted --add-source=10.7.0.0/24
    fi
    clear
    figlet -kE "MTN" | lolcat
    echo -e "\033[1;33mHyper Net Wireguard QR Code\033[0m"
    echo
    qrencode -t ANSIUTF8 < /etc/Wire/"$client.conf"
    echo
    echo -e "\033[1;36m\xE2\x86\x91Snap this QR code and Import it in a Wireguard Client\033[0m"
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
