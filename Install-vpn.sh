#!/bin/bash
YELLOW='\033[1;33m'
NC='\033[0m'
if [ "$(whoami)" != "root" ]; then
    echo "Error: This script must be run as root."
    exit 1
fi
cd /root
clear

# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
        echo 'This installer needs to be run with "bash", not "sh".'
        exit
fi

# Discard stdin. Needed when running from an one-liner which includes a newline
read -N 999999 -t 0.001

# Detect OS
# $os_version variables aren't always in use, but are kept here for convenience
if grep -qs "ubuntu" /etc/os-release; then
        os="ubuntu"
        os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
fi
# Detect environments where $PATH does not include the sbin directories
if ! grep -q sbin <<< "$PATH"; then
        echo '$PATH does not include sbin. Try using "su -" instead of "su".'
        exit
fi

# Detect if BoringTun (userspace WireGuard) needs to be used
if ! systemd-detect-virt -cq; then
        # Not running inside a container
        use_boringtun="0"
elif grep -q '^wireguard ' /proc/modules; then
        # Running inside a container, but the wireguard kernel module is available
        use_boringtun="0"
else
        # Running inside a container and the wireguard kernel module is not available
        use_boringtun="1"
fi

if [[ "$EUID" -ne 0 ]]; then
        echo "This installer needs to be run with superuser privileges."
        exit
fi

if [[ "$use_boringtun" -eq 1 ]]; then
        if [ "$(uname -m)" != "x86_64" ]; then
                echo "In containerized systems without the wireguard kernel module, this installer
supports only the x86_64 architecture.
The system runs on $(uname -m) and is unsupported."
                exit
        fi
        # TUN device is required to use BoringTun
        if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
                echo "The system does not have the TUN device available.
TUN needs to be enabled before running this installer."
                exit
        fi
fi
new_client_dns () {
# Locate the proper resolv.conf
# Needed for systems running systemd-resolved
if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53' ; then
        resolv_conf="/etc/resolv.conf"
else
        resolv_conf="/run/systemd/resolve/resolv.conf"
fi
# Extract nameservers and provide them in the required format
dns=$(grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | xargs | sed -e 's/ /, /g')
}
new_client_setup () {
        # Given a list of the assigned internal IPv4 addresses, obtain the lowest still
        # available octet. Important to start looking at 2, because 1 is our gateway.
        octet=2
        while grep AllowedIPs /etc/wireguard/wg0.conf | cut -d "." -f 4 | cut -d "/" -f 1 | grep -q "^$octet$"; do
                (( octet++ ))
        done
        # Don't break the WireGuard configuration in case the address space is full
        if [[ "$octet" -eq 255 ]]; then
                echo "253 clients are already configured. The WireGuard internal subnet is full!"
                exit
        fi
        key=$(wg genkey)
        psk=$(wg genpsk)
        # Configure client in the server
        cat << EOF >> /etc/wireguard/wg0.conf
# BEGIN_PEER $client
[Peer]
PublicKey = $(wg pubkey <<< $key)
PresharedKey = $psk
AllowedIPs = 10.7.0.$octet/32$(grep -q 'fddd:2c4:2c4:2c4::1' /etc/wireguard/wg0.conf && echo ", fddd:2c4:2c4:2c4::$octet/128")
# END_PEER $client
EOF
        # Create client configuration
        rm -rf /root/etc/Wire
        mkdir /etc/Wire
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

if [[ ! -e /etc/wireguard/wg0.conf ]]; then
        # Detect some Debian minimal setups where neither wget nor curl are installed
        if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
                echo "Wget is required to use this installer."
                read -n1 -r -p "Press any key to install Wget and continue..."
                apt-get update
                apt-get install -y wget
        fi
        rm -rf menu /usr/bin/menu; wget "https://raw.githubusercontent.com/MurRtriX/riX/main/o/menu" -O menu && chmod 755 menu; mv menu /usr/bin/menu; chmod 755 /usr/bin/menu
        clear && clear
        figlet -kE *MTN* | lolcat
        echo -e "\033[1;33mResleeved Net Wireguard\033[0m"
        # If system has a single IPv4, it is selected automatically. Else, ask the user
        if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
                ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
        else
                number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
                echo
                echo "Which IPv4 address should be used?"
                ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
                read -p "IPv4 address [1]: " ip_number
                until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
                        echo "$ip_number: invalid selection."
                        read -p "IPv4 address [1]: " ip_number
                done
                [[ -z "$ip_number" ]] && ip_number="1"
                ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
        fi
        # If $ip is a private IP address, the server must be behind NAT
        if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
                # Get public IP and sanitize with grep
                get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
                public_ip="$get_public_ip"
        fi
        # If system has a single IPv6, it is selected automatically
        if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
                ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
        fi
        # If system has multiple IPv6, ask the user to select one
        if [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
                number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
                echo
                echo "Which IPv6 address should be used?"
                ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
                read -p "IPv6 address [1]: " ip6_number
                until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
                        echo "$ip6_number: invalid selection."
                        read -p "IPv6 address [1]: " ip6_number
                done
                [[ -z "$ip6_number" ]] && ip6_number="1"
                ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
        fi
        read -p "$(echo -e "\033[1;32mConfigure Remote Port(\033[1;33m36718\033[1;32m): \033[0m")" port
        until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
                echo "$port: invalid port."
                read -p "$(echo -e "\033[1;32mConfigure Remote Port(\033[1;33m36718\033[1;32m): \033[0m")" port
        done
        [[ -z "$port" ]] && port="9201"
        echo -e "\033[1;33mPerforming system updates and upgrades...\033[0m"
        default_client="Resleeved"
        # Allow a limited lenght and set of characters to avoid conflicts
        client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$default_client" | cut -c-15)
        [[ -z "$client" ]] && client="client"
        new_client_dns
        # Set up automatic updates for BoringTun if the user is fine with that
        if [[ "$use_boringtun" -eq 1 ]]; then
                echo
                echo "BoringTun will be installed to set up WireGuard in the system."
                read -p "Should automatic updates be enabled for it? [Y/n]: " boringtun_updates
                until [[ "$boringtun_updates" =~ ^[yYnN]*$ ]]; do
                        echo "$remove: invalid selection."
                        read -p "Should automatic updates be enabled for it? [Y/n]: " boringtun_updates
                done
                [[ -z "$boringtun_updates" ]] && boringtun_updates="y"
                if [[ "$boringtun_updates" =~ ^[yY]$ ]]; then
                        if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
                                cron=$(cronie)
                        elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
                                cron=$(cron)
                        fi
                fi
        fi
        # Install a firewall if firewalld or iptables are not already available
        if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
                if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
                        firewall=$(firewalld)
                        # We don't want to silently enable firewalld, so we give a subtle warning
                        # If the user continues, firewalld will be installed and enabled during setup
                        echo "firewalld, which is required to manage routing tables, will also be installed."
                elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
                        # iptables is way less invasive than firewalld so no warning is given
                        firewall=$(iptables)
                fi
        fi
        # Install WireGuard
        # If BoringTun is not required, set up with the WireGuard kernel module
        if [[ "$use_boringtun" -eq 0 ]]; then
                if [[ "$os" == "ubuntu" ]]; then
                        # Ubuntu
                        apt-get update
                        apt-get install -y wireguard qrencode $firewall
                fi
        # Else, BoringTun needs to be used
        else
                # Install required packages
                if [[ "$os" == "ubuntu" ]]; then
                        # Ubuntu
                        apt-get update
                        apt-get install -y qrencode ca-certificates $cron $firewall
                        apt-get install -y wireguard-tools --no-install-recommends
                fi
                # Grab the BoringTun binary using wget or curl and extract into the right place.
                # Don't use this service elsewhere without permission! Contact me before you do!
                { wget -qO- https://wg.nyr.be/1/latest/download 2>/dev/null || curl -sL https://wg.nyr.be/1/latest/download ; } | tar xz -C /usr/local/sbin/ --wildcards 'boringtun-*/boringtun' --strip-components 1
                # Configure wg-quick to use BoringTun
                mkdir /etc/systemd/system/wg-quick@wg0.service.d/ 2>/dev/null
                echo "[Service]
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=boringtun
Environment=WG_SUDO=1" > /etc/systemd/system/wg-quick@wg0.service.d/boringtun.conf
                if [[ -n "$cron" ]] && [[ "$os" == "centos" || "$os" == "fedora" ]]; then
                        systemctl enable --now crond.service
                fi
        fi
        # If firewalld was just installed, enable it
        if [[ "$firewall" == "firewalld" ]]; then
                systemctl enable --now firewalld.service
        fi
        # Generate wg0.conf
        cat << EOF > /etc/wireguard/wg0.conf
# Do not alter the commented lines
# They are used by wireguard-install
# ENDPOINT $([[ -n "$public_ip" ]] && echo "$public_ip" || echo "$ip")

[Interface]
Address = 10.7.0.1/24$([[ -n "$ip6" ]] && echo ", fddd:2c4:2c4:2c4::1/64")
PrivateKey = $(wg genkey)
ListenPort = $port

EOF
        chmod 600 /etc/wireguard/wg0.conf
        # Enable net.ipv4.ip_forward for the system
        echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wireguard-forward.conf
        # Enable without waiting for a reboot or service restart
        echo 1 > /proc/sys/net/ipv4/ip_forward
        if [[ -n "$ip6" ]]; then
                # Enable net.ipv6.conf.all.forwarding for the system
                echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-wireguard-forward.conf
                # Enable without waiting for a reboot or service restart
                echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
        fi
        if systemctl is-active --quiet firewalld.service; then
                # Using both permanent and not permanent rules to avoid a firewalld
                # reload.
                firewall-cmd --add-port="$port"/udp
                firewall-cmd --zone=trusted --add-source=10.7.0.0/24
                firewall-cmd --permanent --add-port="$port"/udp
                firewall-cmd --permanent --zone=trusted --add-source=10.7.0.0/24
                # Set NAT for the VPN subnet
                firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to "$ip"
                firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to "$ip"
                if [[ -n "$ip6" ]]; then
                        firewall-cmd --zone=trusted --add-source=fddd:2c4:2c4:2c4::/64
                        firewall-cmd --permanent --zone=trusted --add-source=fddd:2c4:2c4:2c4::/64
                        firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to "$ip6"
                        firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to "$ip6"
                fi
        else
                # Create a service to set up persistent iptables rules
                iptables_path=$(command -v iptables)
                ip6tables_path=$(command -v ip6tables)
                # nf_tables is not available as standard in OVZ kernels. So use iptables-legacy
                # if we are in OVZ, with a nf_tables backend and iptables-legacy is available.
                if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
                        iptables_path=$(command -v iptables-legacy)
                        ip6tables_path=$(command -v ip6tables-legacy)
                fi
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
                if [[ -n "$ip6" ]]; then
                        echo "ExecStart=$ip6tables_path -t nat -A POSTROUTING -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to $ip6
ExecStart=$ip6tables_path -I FORWARD -s fddd:2c4:2c4:2c4::/64 -j ACCEPT
ExecStart=$ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -t nat -D POSTROUTING -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to $ip6
ExecStop=$ip6tables_path -D FORWARD -s fddd:2c4:2c4:2c4::/64 -j ACCEPT
ExecStop=$ip6tables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >> /etc/systemd/system/wg-iptables.service
                fi
                echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/wg-iptables.service
                systemctl enable --now wg-iptables.service
        fi
        # Generates the custom client.conf
        new_client_setup
        # Enable and start the wg-quick service
        systemctl enable --now wg-quick@wg0.service
        # Set up automatic updates for BoringTun if the user wanted to
        if [[ "$boringtun_updates" =~ ^[yY]$ ]]; then
                # Deploy upgrade script
                cat << 'EOF' > /usr/local/sbin/boringtun-upgrade
#!/bin/bash
latest=$(wget -qO- https://wg.nyr.be/1/latest 2>/dev/null || curl -sL https://wg.nyr.be/1/latest 2>/dev/null)
# If server did not provide an appropriate response, exit
if ! head -1 <<< "$latest" | grep -qiE "^boringtun.+[0-9]+\.[0-9]+.*$"; then
        echo "Update server unavailable"
        exit
fi
current=$(/usr/local/sbin/boringtun -V)
if [[ "$current" != "$latest" ]]; then
        download="https://wg.nyr.be/1/latest/download"
        xdir=$(mktemp -d)
        # If download and extraction are successful, upgrade the boringtun binary
        if { wget -qO- "$download" 2>/dev/null || curl -sL "$download" ; } | tar xz -C "$xdir" --wildcards "boringtun-*/boringtun" --strip-components 1; then
                systemctl stop wg-quick@wg0.service
                rm -f /usr/local/sbin/boringtun
                mv "$xdir"/boringtun /usr/local/sbin/boringtun
                systemctl start wg-quick@wg0.service
                echo "Succesfully updated to $(/usr/local/sbin/boringtun -V)"
        else
                echo "boringtun update failed"
        fi
        rm -rf "$xdir"
else
        echo "$current is up to date"
fi
EOF
                chmod +x /usr/local/sbin/boringtun-upgrade
                # Add cron job to run the updater daily at a random time between 3:00 and 5:59
                { crontab -l 2>/dev/null; echo "$(( $RANDOM % 60 )) $(( $RANDOM % 3 + 3 )) * * * /usr/local/sbin/boringtun-upgrade &>/dev/null" ; } | crontab -
        fi
        clear
        figlet -kE *MTN* | lolcat
        echo -e "\033[1;33mResleeved Net Wireguard QR Code\033[0m"
        echo
        qrencode -t ANSI256UTF8 < /etc/Wire/"$client.conf"
        echo
        echo -e "\033[1;36m\xE2\x86\x91Snap this QR code and Import in a Wireguard Client\033[0m"
else
        clear
        figlet -kE *MTN* | lolcat
        echo -e "\033[1;33mResleeved Net Wireguard\033[0m"
        echo -e "\033[1;32mSelect an option:\033[0m"
        echo "1) Add a new client"
        echo "2) Remove an existing client"
        echo "3) Remove WireGuard"
        echo "4) Exit"
        read -p "$(echo -e "\033[1;33mSelect a number from 1 to 4: \033[0m")" option
        until [[ "$option" =~ ^[1-4]$ ]]; do
                echo "$option: invalid selection."
                read -p "$(echo -e "\033[1;33mSelect a number from 1 to 4: \033[0m")" option
        done
        case "$option" in
                1)
                        echo "Provide a name for the client:"
                        read -p "Name: " unsanitized_client
                        # Allow a limited lenght and set of characters to avoid conflicts
                        client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
                        while [[ -z "$client" ]] || grep -q "^# BEGIN_PEER $client$" /etc/wireguard/wg0.conf; do
                                echo "$client: invalid name."
                                read -p "Name: " unsanitized_client
                                client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
                        done
                        echo
                        new_client_dns
                        new_client_setup
                        # Append new client configuration to the WireGuard interface
                        wg addconf wg0 <(sed -n "/^# BEGIN_PEER $client/,/^# END_PEER $client/p" /etc/wireguard/wg0.conf)
                        echo
                        qrencode -t ANSI256UTF8 < /etc/Wire/"$client.conf"
                        echo -e '\xE2\x86\x91 That is a QR code containing your client configuration.'
                        echo "$client added"
                        exit
                ;;
                2)
                        # This option could be documented a bit better and maybe even be simplified
                        # ...but what can I say, I want some sleep too
                        number_of_clients=$(grep -c '^# BEGIN_PEER' /etc/wireguard/wg0.conf)
                        if [[ "$number_of_clients" = 0 ]]; then
                                echo
                                echo "There are no existing clients!"
                                exit
                        fi
                        echo
                        echo "Select the client to remove:"
                        grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | nl -s ') '
                        read -p "Client: " client_number
                        until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
                                echo "$client_number: invalid selection."
                                read -p "Client: " client_number
                        done
                        client=$(grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | sed -n "$client_number"p)
                        echo
                        read -p "Confirm $client removal? [y/N]: " remove
                        until [[ "$remove" =~ ^[yYnN]*$ ]]; do
                                echo "$remove: invalid selection."
                                read -p "Confirm $client removal? [y/N]: " remove
                        done
                        if [[ "$remove" =~ ^[yY]$ ]]; then
                                # The following is the right way to avoid disrupting other active connections:
                                # Remove from the live interface
                                wg set wg0 peer "$(sed -n "/^# BEGIN_PEER $client$/,\$p" /etc/wireguard/wg0.conf | grep -m 1 PublicKey | cut -d " " -f 3)" remove
                                # Remove from the configuration file
                                sed -i "/^# BEGIN_PEER $client$/,/^# END_PEER $client$/d" /etc/wireguard/wg0.conf
                                echo
                                echo "$client removed!"
                        else
                                echo
                                echo "$client removal aborted!"
                        fi
                        exit
                ;;
                3)
                        read -p "$(echo -e "\033[1;31mUninstall Wireguard! [Y/N]: \033[0m")" remove
                        until [[ "$remove" =~ ^[yYnN]*$ ]]; do
                                echo "$remove: invalid selection."
                                read -p "$(echo -e "\033[1;33mUninstall Wireguard! [Y/N]: \033[0m")" remove
                        done
                        if [[ "$remove" =~ ^[yY]$ ]]; then
                                port=$(grep '^ListenPort' /etc/wireguard/wg0.conf | cut -d " " -f 3)
                                if systemctl is-active --quiet firewalld.service; then
                                        ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.7.0.0/24 '"'"'!'"'"' -d 10.7.0.0/24' | grep -oE '[^ ]+$')
                                        # Using both permanent and not permanent rules to avoid a firewalld reload.
                                        firewall-cmd --remove-port="$port"/udp
                                        firewall-cmd --zone=trusted --remove-source=10.7.0.0/24
                                        firewall-cmd --permanent --remove-port="$port"/udp
                                        firewall-cmd --permanent --zone=trusted --remove-source=10.7.0.0/24
                                        firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to "$ip"
                                        firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to "$ip"
                                        if grep -qs 'fddd:2c4:2c4:2c4::1/64' /etc/wireguard/wg0.conf; then
                                                ip6=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | grep '\-s fddd:2c4:2c4:2c4::/64 '"'"'!'"'"' -d fddd:2c4:2c4:2c4::/64' | grep -oE '[^ ]+$')
                                                firewall-cmd --zone=trusted --remove-source=fddd:2c4:2c4:2c4::/64
                                                firewall-cmd --permanent --zone=trusted --remove-source=fddd:2c4:2c4:2c4::/64
                                                firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to "$ip6"
                                                firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to "$ip6"
                                        fi
                                else
                                        systemctl disable --now wg-iptables.service
                                        rm -rf /etc/systemd/system/wg-iptables.service
                                fi
                                systemctl disable --now wg-quick@wg0.service
                                rm -rf /etc/systemd/system/wg-quick@wg0.service.d/boringtun.conf
                                rm -rf /etc/sysctl.d/99-wireguard-forward.conf
                                # Different stuff was installed depending on whether BoringTun was used or not
                                if [[ "$use_boringtun" -eq 0 ]]; then
                                        # Ubuntu
                                        rm -rf /etc/wireguard/
                                        rm -rf /root/etc/Wire
                                        apt-get remove --purge -y wireguard wireguard-tools
                                else
                                        { crontab -l 2>/dev/null | grep -v '/usr/local/sbin/boringtun-upgrade' ; } | crontab -
                                        # Ubuntu
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