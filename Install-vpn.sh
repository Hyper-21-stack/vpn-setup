#!/bin/bash
YELLOW='\033[1;33m'
NC='\033[0m'
if [ "$(whoami)" != "root" ]; then
    echo "Error: This script must be run as root."
    exit 1
fi
cd /root
clear
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
figlet -kE *MTN* | lolcat
echo -e "\033[1;33m   Resleeved Net Wireguard\033[0m"
        echo -e "\033[1;32m   Select an option:\033[0m"
        echo "   1) Add a new client"
        echo "   2) View Client QR"
        echo "   3) Delete client"
        echo "   4) Remove WireGuard"
        echo "   5) Exit"
        read -p "$(echo -e "\033[1;33m   Select a number from 1 to 5: \033[0m")" option
        until [[ "$option" =~ ^[1-5]$ ]]; do
                echo "$option: invalid selection."
                read -p "$(echo -e "\033[1;33mSelect a number from 1 to 5: \033[0m")" option
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
                        qrencode -t ANSIUTF8 < /etc/Wire/"$client.conf"
                        echo -e '\xE2\x86\x91 That is a QR code containing your client configuration.'
                        echo "$client added"
                        exit
                ;;
                2)
                        clear
                        figlet -kE *MTN* | lolcat
                        echo -e "\033[1;33mActive Wireguard Clients\033[0m"
                        grep -E '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3
                        read -p "$(echo -e "\033[1;33mSelect Client to View QR code :\033[0m")" client
                        echo
                        echo -e "\033[1;33mResleeved Net Wireguard QR Code\033[0m"
                        echo 
                        qrencode -t ANSIUTF8 < /etc/Wire/"$client.conf"
                        echo
                        echo -e "\033[1;36mSnap this QR code and Import in a Wireguard Client\033[0m"
                        exit
                ;;
                3)
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
                4)
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
                                        rm -rf /etc/Wire
                                        apt-get remove --purge -y wireguard wireguard-tools
                                else
                                        { crontab -l 2>/dev/null | grep -v '/usr/local/sbin/boringtun-upgrade' ; } | crontab -
                                        # Ubuntu
                                        rm -rf /etc/wireguard/
                                        rm -rf /etc/Wire
                                        apt-get remove --purge -y wireguard-tools
                                        rm -rf /usr/local/sbin/boringtun /usr/local/sbin/boringtun-upgrade
                                fi
                                echo "WireGuard removed!"
                        else
                                echo "WireGuard removal aborted!"
                        fi
                        exit
                ;;
                5)
                        exit
                ;;
        esac
fi