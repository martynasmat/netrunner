from scapy.all import *
from scapy.layers.dot11 import *

def handle_beacon(pkt):

    # Filter beacon frames
    # 802.11 specifies management frames as type 0 and beacon frames as subtype 8
    if pkt.haslayer(Dot11Beacon) and pkt[Dot11].type == 0 and pkt[Dot11].subtype == 8:
        bssid = pkt[Dot11].addr3
        ssid = pkt[Dot11Elt].info.decode()
        print(f'BSSID: {bssid} SSID: {ssid}')


sniff(iface="wlan0mon", prn=handle_beacon, store=0)