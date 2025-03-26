from scapy.all import *
import scapy

def handle_beacon(pkt):

    # Filter beacon frames
    if pkt.haslayer(scapy.layers.dot11.Dot11Beacon):
        print('yes')


sniff(iface="wlan0mon", prn=handle_beacon, store=0)