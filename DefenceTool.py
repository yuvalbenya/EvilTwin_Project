from scapy.all import *
import logging
from scapy.layers.dot11 import Dot11, RadioTap, Dot11Deauth, Dot11Elt, Dot11FCS
import os
import argparse
from multiprocessing import Process
import threading as t


count = 0

def defence(iface):
    sniff(iface=iface, prn=pkt_handler)


def pkt_handler(pkt):
    global count
    if pkt.haslayer(Dot11FCS):
        if pkt.type == 0 and pkt.subtype == 0xC:
            count = count + 1
    if count > 50:
        print("someone under attack!")