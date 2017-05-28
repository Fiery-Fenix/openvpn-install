# openvpn-install.sh
OpenVPN server installer script based on Nyr "road-warrior" script

## Supported features
* Can setup OpenVPN server in 3 modes: UDP, TCP or Mikrotik-specific TCP
* Automaticly install needed software and generate all needed stuff
* Add/Revoke users per installation type
* Max 3 instances of OpenVPN server (one per each type)
* Full traffic routing or based on subnets list
* Can install on Debian-based and CentOS-based distros
* Minimal intersection with exiting networks
* Different DNS servers for domain resolution

## Requirements
* Debian, Ubuntu or CentOS
* Bash
* Static public IP
