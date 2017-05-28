#!/bin/bash
# OpenVPN road warrior installer for Debian, Ubuntu and CentOS

# This script will work on Debian, Ubuntu, CentOS and probably other distros
# of the same families, although no support is offered for them. It isn't
# bulletproof but it will probably work if you simply want to setup a VPN on
# your Debian/Ubuntu/CentOS box. It has been designed to be as unobtrusive and
# universal as possible.

# Based on Nyr "road-warrior" script from
# https://raw.githubusercontent.com/Nyr/openvpn-install/master/openvpn-install.sh

############################
# Env Detection
############################
# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -qs "dash"; then
	echo "This script needs to be run with bash, not sh"
	exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "Sorry, you need to run this as root"
	exit 2
fi

if [[ ! -e /dev/net/tun ]]; then
	echo "The TUN device is not available
You need to enable TUN before running this script"
	exit 3
fi

if grep -qs "CentOS release 5" "/etc/redhat-release"; then
	echo "CentOS 5 is too old and not supported"
	exit 4
fi
if [[ -e /etc/debian_version ]]; then
	OS=debian
	GROUPNAME=nogroup
	RCLOCAL="/etc/rc.local"
elif [[ -e /etc/centos-release || -e /etc/redhat-release ]]; then
	OS=centos
	GROUPNAME=nobody
	RCLOCAL="/etc/rc.d/rc.local"
else
	echo "Looks like you aren't running this installer on Debian, Ubuntu or CentOS"
	exit 5
fi

############################
# Variables
############################
SERVER_LIST="/etc/openvpn/servers.list"
CLIENT_LIST="/etc/openvpn/clients.list"
UDP_SERVER=0
UDP_SERVER_PORT=
UDP_SERVER_SUBNET=
UDP_SUBNET="172.17.0.0/24"
TCP_SERVER=0
TCP_SERVER_PORT=
TCP_SERVER_SUBNET=
TCP_SUBNET="172.18.0.0/24"
MIKROTIK_SERVER=0
MIKROTIK_SERVER_PORT=
MIKROTIK_SERVER_SUBNET=
MIKROTIK_SUBNET="172.19.0.0/24"
DNS_CONFIG=""
ROUTES_CONFIG=""
IP=$(wget -4qO- "http://whatismyip.akamai.com/")

############################
# Usefull functions
############################
#=========================================
# General functions
#=========================================
read_servers_from_config() {
	if [[ -e $SERVER_LIST ]]; then
		while read def; 
		do
			if [[ ! -z "${def// }" ]]; then
				# Expose defenitions
				case $def in
					tcp*)
						arr=($def)
						TCP_SERVER_PORT="${arr[1]}"
						TCP_SERVER_SUBNET="${arr[2]}"
						TCP_SERVER=1
					;;
					udp*)
						arr=($def)
						UDP_SERVER_PORT="${arr[1]}"
						UDP_SERVER_SUBNET="${arr[2]}"
						UDP_SERVER=1
					;;
					mikrotik*)
						arr=($def)
						MIKROTIK_SERVER_PORT="${arr[1]}"
						MIKROTIK_SERVER_SUBNET="${arr[2]}"
						MIKROTIK_SERVER=1
					;;
				esac
			fi
		done <<< "$(cat $SERVER_LIST)"
	fi
}

get_dns_for_config() {
	case $1 in
		1) 
			# Obtain the resolvers from resolv.conf and use them for OpenVPN
			grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
				DNS_CONFIG="$DNS_CONFIG
push \"dhcp-option DNS $line\""
			done
		;;
		2)
			DNS_CONFIG='push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"'
		;;
		3)
			DNS_CONFIG='push "dhcp-option DNS 208.67.222.222"
push "dhcp-option DNS 208.67.220.220"'
		;;
		4) 
			DNS_CONFIG='push "dhcp-option DNS 129.250.35.250"
push "dhcp-option DNS 129.250.35.251"'
		;;
		5) 
			DNS_CONFIG='push "dhcp-option DNS 74.82.42.42"'
		;;
		6) 
			DNS_CONFIG='push "dhcp-option DNS 64.6.64.6"
push "dhcp-option DNS 64.6.65.6"'
		;;
	esac
}

get_routes_for_config() {
	ROUTES=$1
	if [[ -e $ROUTES ]]; then
		while read -r def; 
		do
			if [[ ! -z "${def// }" ]]; then
				ROUTES_CONFIG="$ROUTES_CONFIG
push \"route $def\""
			fi
		done <<< "$(cat $ROUTES)" 
	fi
}

#+++++++++++++++++++++++++++++++++++++++++
# Creation functions
#+++++++++++++++++++++++++++++++++++++++++
## Generates new client config for TCP/UDP TLS-based setup
## $1 - client name
## $2 - [tcp|udp|mikrotik] - type of config
new_client() {
	CLIENT_NAME=$1
	CLIENT_TYPE=$2

	# Generates certificates
	cd /etc/openvpn/easy-rsa/
	./easyrsa build-client-full $CLIENT_NAME nopass

	if [[ "$CLIENT_TYPE" = 'mikrotik' ]]; then
		new_client_mikrotik "$CLIENT_NAME"
	else
		# Generates the custom client.ovpn
		cp /etc/openvpn/client-common-$CLIENT_TYPE.txt ~/$CLIENT_NAME.ovpn
		echo "<ca>" >> ~/$CLIENT_NAME.ovpn
		cat /etc/openvpn/easy-rsa/pki/ca.crt >> ~/$CLIENT_NAME.ovpn
		echo "</ca>" >> ~/$CLIENT_NAME.ovpn
		echo "<cert>" >> ~/$CLIENT_NAME.ovpn
		cat /etc/openvpn/easy-rsa/pki/issued/$CLIENT_NAME.crt >> ~/$CLIENT_NAME.ovpn
		echo "</cert>" >> ~/$CLIENT_NAME.ovpn
		echo "<key>" >> ~/$CLIENT_NAME.ovpn
		cat /etc/openvpn/easy-rsa/pki/private/$CLIENT_NAME.key >> ~/$CLIENT_NAME.ovpn
		echo "</key>" >> ~/$CLIENT_NAME.ovpn
		echo "<tls-auth>" >> ~/$CLIENT_NAME.ovpn
		cat /etc/openvpn/ta.key >> ~/$CLIENT_NAME.ovpn
		echo "</tls-auth>" >> ~/$CLIENT_NAME.ovpn
		
		echo "$CLIENT_TYPE $CLIENT_NAME" >> $CLIENT_LIST
		echo ""
		echo "Client $CLIENT added, configuration is available at ~/$CLIENT_NAME.ovpn"
	fi
}

new_client_mikrotik() {
	mkdir -p ~/$1
	cp /etc/openvpn/client-mikrotik.auto.rsc ~/$1/client-mikrotik.auto.rsc

	cat /etc/openvpn/easy-rsa/pki/ca.crt >> ~/$1/ca.crt
	cat /etc/openvpn/easy-rsa/pki/issued/$1.crt >> ~/$1/client-mikrotik.crt
	openssl rsa -in /etc/openvpn/easy-rsa/pki/private/$1.key -out ~/$1/client-mikrotik.pem
	tar -czf ~/$1.tar.gz ~/$1/
	
	echo "mikrotik $CLIENT_NAME" >> $CLIENT_LIST
	echo ""
	echo "Client $CLIENT added, configuration archive is available at ~/$1.tar.gz"
}

install_openvpn() {
	if [[ "$OS" = 'debian' ]]; then
		apt-get update
		apt-get install openvpn iptables openssl ca-certificates -y
	else
		# Else, the distro is CentOS
		yum install epel-release -y
		yum install openvpn iptables openssl wget ca-certificates -y
	fi
}

install_easyrsa() {
	# An old version of easy-rsa was available by default in some openvpn packages
	if [[ -d /etc/openvpn/easy-rsa/ ]]; then
		rm -rf /etc/openvpn/easy-rsa/
	fi
	# Get easy-rsa
	wget -O ~/EasyRSA-3.0.1.tgz "https://github.com/OpenVPN/easy-rsa/releases/download/3.0.1/EasyRSA-3.0.1.tgz"
	tar xzf ~/EasyRSA-3.0.1.tgz -C ~/
	mv ~/EasyRSA-3.0.1/ /etc/openvpn/
	mv /etc/openvpn/EasyRSA-3.0.1/ /etc/openvpn/easy-rsa/
	chown -R root:root /etc/openvpn/easy-rsa/
	rm -rf ~/EasyRSA-3.0.1.tgz
}

generate_server_certs() {
	cd /etc/openvpn/easy-rsa/
	# Create the PKI, set up the CA, the DH params and the server certificates
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	./easyrsa gen-dh
	./easyrsa build-server-full server nopass
	./easyrsa gen-crl
	# Move the stuff we need
	cp pki/ca.crt pki/private/ca.key pki/dh.pem pki/issued/server.crt pki/private/server.key /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn
	# CRL is read with each client connection, when OpenVPN is dropped to nobody
	chown nobody:$GROUPNAME /etc/openvpn/crl.pem
	# Generate key for tls-auth
	openvpn --genkey --secret /etc/openvpn/ta.key
}

generate_tsl_config() {
	PORT=$1
	PROTO="${2/mikrotik/tcp}"
	SUBNET=$3
	DNS=$4
	ROUTES=$5
	
	SERVER_CONFIG="/etc/openvpn/server-$2-$PORT.conf"
	
	# Get DNS string
	get_dns_for_config "$DNS"
	
	echo "port $PORT
proto $PROTO
dev tun
sndbuf 0
rcvbuf 0
ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-auth ta.key 0
topology subnet
server ${SUBNET/\/24/ 255.255.255.0}
ifconfig-pool-persist ipp.txt" > $SERVER_CONFIG
	if [[ -z "${ROUTES// }" ]]; then echo 'push "redirect-gateway def1 bypass-dhcp"' >> $SERVER_CONFIG; fi
	if [[ ! -z "${ROUTES// }" ]]; then 
		get_routes_for_config "$ROUTES"
		echo "$ROUTES_CONFIG" >> $SERVER_CONFIG
	fi
	echo "$DNS_CONFIG" >> $SERVER_CONFIG
	echo "keepalive 10 120
cipher AES-256-CBC
comp-lzo
user nobody
group $GROUPNAME
persist-key
persist-tun
status openvpn-status.log
verb 3
crl-verify crl.pem" >> $SERVER_CONFIG
}

generate_mikrotik_config() {
	PORT=$1
	SUBNET=$3
	DNS=$4
	ROUTES=$5
	
	SERVER_CONFIG="/etc/openvpn/server-mikrotik-$PORT.conf"
	
	# Get DNS string
	get_dns_for_config "$DNS"
	
	echo "port $PORT
proto tcp
dev tun
sndbuf 0
rcvbuf 0
ca ca.crt
cert server.crt
key server.key
dh dh.pem
topology subnet
server ${SUBNET/\/24/ 255.255.255.0}
ifconfig-pool-persist ipp.txt" > $SERVER_CONFIG
	if [[ -z "${ROUTES// }" ]]; then echo 'push "redirect-gateway def1 bypass-dhcp"' >> $SERVER_CONFIG; fi
	if [[ ! -z "${ROUTES// }" ]]; then 
		get_routes_for_config "$ROUTES"
		echo "$ROUTES_CONFIG" >> $SERVER_CONFIG
	fi
	echo "$DNS_CONFIG" >> $SERVER_CONFIG
	echo "keepalive 10 120
cipher AES-256-CBC
user nobody
group $GROUPNAME
persist-key
persist-tun
status openvpn-status.log
verb 3
crl-verify crl.pem" >> $SERVER_CONFIG
}

generate_client_template() {
	PORT=$1
	PROTO="${2/mikrotik/tcp}"
	ROUTES=$3
	BLOCK_DNS_OUT=

	if [[ -z "${ROUTES// }" ]]; then BLOCK_DNS_OUT="setenv opt block-outside-dns"; fi

	echo "client
dev tun
proto $PROTO
sndbuf 0
rcvbuf 0
remote $IP $PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
comp-lzo
$BLOCK_DNS_OUT
key-direction 1
verb 3" > /etc/openvpn/client-common-$2.txt
}

generate_mikrotik_script() {
	PORT=$1
	PROTO="tcp"
	ROUTES=$3
	CUSTOM_ROUTES=

	echo "/certificate import file-name=ca.crt passphrase=no
/certificate import file-name=client-mikrotik.crt passphrase=no
/certificate import file=client-mikrotik.pem passphrase=no
/ppp profile add use-mpls=no use-compression=no use-encryption=yes name=openvpn-client
/interface ovpn-client add name=\"ovpn-out1\" connect-to=$IP port=$PORT mode=ip user=\"username\" password=\"password\" profile=openvpn-client certificate=client-mikrotik cipher=aes256 add-default-route=no
/ip firewall nat add chain=srcnat out-interface=ovpn-out1 action=masquerade
" > /etc/openvpn/client-mikrotik.auto.rsc
}

setup_network() {
	PORT=$1
	PROTO=$2
	SUBNET=$3

	if [[ "$IP" = "" ]]; then
		echo "Unknown IP, can't process network reconfiguration!"
		exit 6
	fi

	# Enable net.ipv4.ip_forward for the system
	sed -i '/\<net.ipv4.ip_forward\>/c\net.ipv4.ip_forward=1' /etc/sysctl.conf
	if ! grep -q "\<net.ipv4.ip_forward\>" /etc/sysctl.conf; then
		echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
	fi
	
	# Avoid an unneeded reboot
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if pgrep firewalld; then
		# Using both permanent and not permanent rules to avoid a firewalld
		# reload.
		# We don't use --add-service=openvpn because that would only work with
		# the default port and protocol.
		firewall-cmd --zone=public --add-port=$PORT/$PROTO
		firewall-cmd --zone=trusted --add-source=$SUBNET
		firewall-cmd --permanent --zone=public --add-port=$PORT/$PROTO
		firewall-cmd --permanent --zone=trusted --add-source=$SUBNET
		# Set NAT for the VPN subnet
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s $SUBNET ! -d $SUBNET -j SNAT --to $IP
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s $SUBNET ! -d $SUBNET -j SNAT --to $IP
	else
		# Needed to use rc.local with some systemd distros
		if [[ "$OS" = 'debian' && ! -e $RCLOCAL ]]; then
			echo '#!/bin/sh -e
exit 0' > $RCLOCAL
		fi
		chmod +x $RCLOCAL
		# Set NAT for the VPN subnet
		iptables -t nat -A POSTROUTING -s $SUBNET ! -d $SUBNET -j SNAT --to $IP
		sed -i "1 a\iptables -t nat -A POSTROUTING -s $SUBNET ! -d $SUBNET -j SNAT --to $IP" $RCLOCAL
		if iptables -L -n | grep -qE '^(REJECT|DROP)'; then
			# If iptables has at least one REJECT rule, we asume this is needed.
			# Not the best approach but I can't think of other and this shouldn't
			# cause problems.
			iptables -I INPUT -p $PROTO --dport $PORT -j ACCEPT
			iptables -I FORWARD -s $SUBNET -j ACCEPT
			iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
			sed -i "1 a\iptables -I INPUT -p $PROTO --dport $PORT -j ACCEPT" $RCLOCAL
			sed -i "1 a\iptables -I FORWARD -s $SUBNET -j ACCEPT" $RCLOCAL
			sed -i "1 a\iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" $RCLOCAL
		fi
	fi
	
	# If SELinux is enabled and a custom port or TCP was selected, we need this
	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			if [[ "$PORT" != '1194' || "$PROTO" = 'tcp' ]]; then
				# semanage isn't available in CentOS 6 by default
				if ! hash semanage 2>/dev/null; then
					yum install policycoreutils-python -y
				fi
				semanage port -a -t openvpn_port_t -p $PROTO $PORT
			fi
		fi
	fi
}

create_new_server() {
	PORT=$1
	PROTO="${2/mikrotik/tcp}"
	DNS=$3
	ROUTES=$4
	
	SERVER_CONFIG="/etc/openvpn/server-$2-$PORT.conf"
	
	# Generate server config
	case $2 in
		udp)
			SUBNET="$UDP_SUBNET"
			generate_tsl_config "$PORT" "$PROTO" "$SUBNET" "$DNS" "$ROUTES"
		;;
		tcp)
			SUBNET="$TCP_SUBNET"
			generate_tsl_config "$PORT" "$PROTO" "$SUBNET" "$DNS" "$ROUTES"
		;;
		mikrotik)
			SUBNET="$MIKROTIK_SUBNET"
			generate_mikrotik_config "$PORT" "$2" "$SUBNET" "$DNS" "$ROUTES"
		;;
	esac
	
	# Generate client template
	if [[ "$2" = 'mikrotik' ]]; then
		generate_mikrotik_script "$PORT" "$2" "$ROUTES"
	else
		generate_client_template "$PORT" "$2" "$ROUTES"
	fi
	
	# Make needed network changes
	setup_network "$PORT" "$PROTO" "$SUBNET"
	
	# And finally, restart OpenVPN
	if [[ "$OS" = 'debian' ]]; then
		# Little hack to check for systemd
		if pgrep systemd-journal; then
			systemctl restart openvpn@server-$2-$PORT.service
		else
			/etc/init.d/openvpn restart
		fi
	else
		if pgrep systemd-journal; then
			systemctl restart openvpn@server-$2-$PORT.service
			systemctl enable openvpn@server-$2-$PORT.service
		else
			service openvpn restart
			chkconfig openvpn on
		fi
	fi
	
	
	# Finally, add to config
	echo "$2 $PORT $SUBNET" >> $SERVER_LIST
}

#-----------------------------------------
# Removal functions
#-----------------------------------------
remove_client() {
	CLIENT=$1

	cd /etc/openvpn/easy-rsa/
	./easyrsa --batch revoke $CLIENT
	./easyrsa gen-crl
	rm -rf pki/reqs/$CLIENT.req
	rm -rf pki/private/$CLIENT.key
	rm -rf pki/issued/$CLIENT.crt
	rm -rf /etc/openvpn/crl.pem
	cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
	# CRL is read with each client connection, when OpenVPN is dropped to nobody
	chown nobody:$GROUPNAME /etc/openvpn/crl.pem
	echo ""
	echo "Certificate for client $CLIENT revoked"
}

remove_clients_server() {
	PROTO=$1

	while read -r type name;
	do
		if [[ "$type" = "$PROTO" ]]; then
			remove_client "$name"
		fi
	done <<< "$(cat $CLIENT_LIST)" 

	sed -i "/^$type/d" $CLIENT_LIST
}

remove_server() {
	PROTO="${1/mikrotik/tcp}"
	PORT=$2
	SUBNET=$3

	if [[ "$IP" = "" ]]; then
		echo "Unknown IP, can't process network reconfiguration!"
		exit 6
	fi

	if pgrep firewalld; then
		TO_IP=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s $SUBNET '"'"'!'"'"' -d $SUBNET -j SNAT --to ' | cut -d " " -f 10)
		if [[ "$TO_IP" != "" ]]; then
			# Using both permanent and not permanent rules to avoid a firewalld reload.
			firewall-cmd --zone=public --remove-port=$PORT/$PROTO
			firewall-cmd --zone=trusted --remove-source=$SUBNET
			firewall-cmd --permanent --zone=public --remove-port=$PORT/$PROTO
			firewall-cmd --permanent --zone=trusted --remove-source=$SUBNET
			firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s $SUBNET ! -d $SUBNET -j SNAT --to $TO_IP
			firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s $SUBNET ! -d $SUBNET -j SNAT --to $TO_IP
		else
			echo "No rules found, skipping network reconfiguration..."
		fi
	else
		TO_IP=$(grep 'iptables -t nat -A POSTROUTING -s $SUBNET ! -d $SUBNET -j SNAT --to ' $RCLOCAL | cut -d " " -f 11)
		if [[ "$TO_IP" != "" ]]; then
			iptables -t nat -D POSTROUTING -s $SUBNET ! -d $SUBNET -j SNAT --to $TO_IP
			sed -i "\~iptables -t nat -A POSTROUTING -s $SUBNET ! -d $SUBNET -j SNAT --to ~d" $RCLOCAL
			if iptables -L -n | grep -qE '^ACCEPT'; then
				iptables -D INPUT -p $PROTO --dport $PORT -j ACCEPT
				iptables -D FORWARD -s $SUBNET -j ACCEPT
				iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
				sed -i "/iptables -I INPUT -p $PROTO --dport $PORT -j ACCEPT/d" $RCLOCAL
				sed -i "\~iptables -I FORWARD -s $SUBNET -j ACCEPT~d" $RCLOCAL
				sed -i "/iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT/d" $RCLOCAL
			fi
		else
			echo "No rules found, skipping network reconfiguration..."
		fi
	fi
	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			if [[ "$PORT" != '1194' || "$PROTO" = 'tcp' ]]; then
				semanage port -d -t openvpn_port_t -p $PROTO $PORT
			fi
		fi
	fi
	
	# Stop the server
	if pgrep systemd-journal; then
		systemctl stop openvpn@server-$1-$PORT.service
		rm -f /etc/openvpn/server-$1-$PORT.conf
	else
		rm -f /etc/openvpn/server-$1-$PORT.conf
		/etc/init.d/openvpn restart
	fi

	rm -f /etc/openvpn/server-$1-$PORT.conf
	
	# Remove server from registry
	sed -i "/^$1/d" $SERVER_LIST

	# Remove client from registry
	remove_clients_server "$1"

	echo ""
	echo "Server $PORT:$PROTO with subnet $SUBNET removed!"
}

remove_package() {
	if [[ "$OS" = 'debian' ]]; then
		apt-get remove --purge -y openvpn openvpn-blacklist
	else
		yum remove openvpn -y
	fi
	rm -rf /etc/openvpn
	rm -rf /usr/share/doc/openvpn*
}

#*****************************************
# Submenu functions
#*****************************************
submenu_new_user() {
	clear
	echo "Generating new user"
	echo ""
	echo "What user do you whant to create?"
	echo "   1) TCP user (preferred for usage in mobile network)"
	echo "   2) UDP user (recommended for usage in classic networks)"
	echo "   3) Mikrotik user (TCP only, without LZO compression, login+pass auth)"
	echo "   4) Exit"
	read -p "Select an option [1-4]: " usertype
	case $usertype in
		1)
			echo ""
			echo "Tell me a name for the client certificate"
			echo "Please, use one word only, no special characters"
			read -p "Client name: " -e -i client CLIENT
			new_client "$CLIENT" "tcp"
		;;
		2)
			echo ""
			echo "Tell me a name for the client certificate"
			echo "Please, use one word only, no special characters"
			read -p "Client name: " -e -i client CLIENT
			new_client "$CLIENT" "udp"
		;;
		3)
			echo ""
			echo "Tell me a name for the client certificate"
			echo "Please, use one word only, no special characters"
			read -p "Client name: " -e -i client CLIENT
			new_client_mikrotik "$CLIENT"
		;;
		4) 
		;;
	esac
}

submenu_drop_user() {
	# This option could be documented a bit better and maybe even be simplimplified
	# ...but what can I say, I want some sleep too
	NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
	if [[ "$NUMBEROFCLIENTS" = '0' ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 6
	fi
	echo ""
	echo "Select the existing client certificate you want to revoke"
	tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
	if [[ "$NUMBEROFCLIENTS" = '1' ]]; then
		read -p "Select one client [1]: " CLIENTNUMBER
	else
		read -p "Select one client [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
	fi
	CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
	remove_client "$CLIENT"
}

submenu_new_server() {
	echo "I need to ask you a few questions for the setup"
	echo "You can leave the default options and just press enter if you are ok with them"
	echo ""
	echo "First I need to know the IPv4 address of the network interface you want OpenVPN"
	echo "listening to."
	read -p "IP address: " -e -i $IP IP

	echo ""
	echo "What server do you with to install for OpenVPN connections?"
	echo "   1) UDP (recommended for stable connections)"
	echo "   2) TCP (recommended for modile connections)"
	echo "   3) Microtik (TCP only, no LZO compression, password auth)"
	read -p "Protocol [1-3]: " -e -i 1 PROTOCOL
	case $PROTOCOL in
		1) 
			PROTOCOL=udp
		;;
		2) 
			PROTOCOL=tcp
		;;
		3)
			PROTOCOL=mikrotik
		;;
	esac

	echo ""
	echo "What port do you want your OpenVPN listening to?"
	read -p "Port: " -e -i 1194 PORT

	echo ""
	echo "Which DNS do you want to use with the VPN?"
	echo "   1) Current system resolvers"
	echo "   2) Google"
	echo "   3) OpenDNS"
	echo "   4) NTT"
	echo "   5) Hurricane Electric"
	echo "   6) Verisign"
	read -p "DNS [1-6]: " -e -i 1 DNS
	
	echo ""
	echo "Do you want to setup VPN for whole traffic or for specified subnets?"
	echo "For whole traffic - leave it emtpy"
	echo "For subnet VPN - provide path to file with subnets list"
	echo "Format of subnets list is 'ip subnet' on each line, nothing else shoul be there!"
	echo "For example: "
	echo "192.168.1.0 255.255.255.0"
	echo "192.168.2.0 255.255.255.0"
	read -p "Subnets list file: " -e ROUTES

	echo ""
	echo "Finally, tell me your name for the client certificate"
	echo "Please, use one word only, no special characters"
	read -p "Client name: " -e -i client CLIENT

	echo ""
	echo "Okay, that was all I needed. We are ready to setup your OpenVPN server now"
	read -n1 -r -p "Press any key to continue..."

	# Generate server.conf and client template for this server
	create_new_server "$PORT" "$PROTOCOL" "$DNS" "$ROUTES"

	# Generates the custom client.ovpn
	new_client "$CLIENT" "$PROTOCOL"
	echo ""
	echo "Finished!"
}

############################
# End of Usefull functions
############################
if [[ -e $SERVER_LIST ]]; then
	while :
	do
		clear
		read_servers_from_config
		echo ""
		echo "Looks like OpenVPN is already installed"
		echo ""
		echo "What do you want to do?"
		echo "   1) Add a new user"
		echo "   2) Revoke an existing user"
		echo "   3) Add OpenVPN server (TCP/UDP/Mikrotik)"
		echo "   4) Remove OpenVPN server (TCP/UDP/Mikrotik)"
		echo "   5) Totally remove OpenVPN from server"
		echo "   6) Exit"
		read -p "Select an option [1-6]: " option
		case $option in
			1) 
				submenu_new_user
				exit
			;;
			2)
				submenu_drop_user
				exit
			;;
			3)
				submenu_new_server
				exit
			;;
			4)
				echo ""
				echo "Which server do you want to remove?"
				if [ $TCP_SERVER != 0 ]; then echo "   tcp) TCP Server on port $TCP_SERVER_PORT subnet $TCP_SERVER_SUBNET"; fi
				if [ $UDP_SERVER != 0 ]; then echo "   udp) UDP Server on port $UDP_SERVER_PORT subnet $UDP_SERVER_SUBNET"; fi
				if [ $MIKROTIK_SERVER != 0 ]; then echo "   mikrotik) TCP Server on port $MIKROTIK_SERVER_PORT subnet $MIKROTIK_SERVER_SUBNET"; fi
				read -p "Server: " -e SERVER_TYPE
				case $SERVER_TYPE in
					tcp)
						remove_server "tcp" "$TCP_SERVER_PORT" "$TCP_SERVER_SUBNET"
						exit
					;;
					udp)
						remove_server "udp" "$UDP_SERVER_PORT" "$UDP_SERVER_SUBNET"
						exit
					;;
					mikrotik)
						remove_server "mikrotik" "$MIKROTIK_SERVER_PORT" "$MIKROTIK_SERVER_SUBNET"
						exit
					;;
				esac
				exit
			;;
			5)
				echo ""
				read -p "Do you really want to completely remove OpenVPN? [y/n]: " -e -i n REMOVE
				if [[ "$REMOVE" = 'y' ]]; then
					if [ $TCP_SERVER != 0 ]; then remove_server "tcp" "$TCP_SERVER_PORT" "$TCP_SERVER_SUBNET"; fi
					if [ $UDP_SERVER != 0 ]; then remove_server "udp" "$UDP_SERVER_PORT" "$UDP_SERVER_SUBNET"; fi
					if [ $MIKROTIK_SERVER != 0 ]; then remove_server "mikrotik" "$MIKROTIK_SERVER_PORT" "$MIKROTIK_SERVER_SUBNET"; fi
					remove_package
					echo ""
					echo "OpenVPN removed!"
				else
					echo ""
					echo "Removal aborted!"
				fi
				exit
			;;
			4) exit;;
		esac
	done
else
	clear
	echo 'Welcome to this quick OpenVPN "road warrior" installer'

	echo ""
	echo "This script first install all needed software and then run step-by-step wizard to setup server"
	echo "Lets start?"
	read -n1 -r -p "Press any key to continue..."
	
	echo ""
	echo "Installing required software..."
	install_openvpn
	install_easyrsa
	
	echo ""
	echo "Required software is intalled, next - generate certificates, can take some time..."
	generate_server_certs

	submenu_new_server

	echo ""
	echo "Finished!"
	echo ""
	echo "If you want to add more clients or servers, you simply need to run this script again!"
fi
