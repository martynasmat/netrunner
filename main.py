from scapy.all import *
from scapy.layers.dot11 import *
import threading
from change_channel import change_channel

INTERFACE_NAME = 'wlan0mon'
START_CHANNEL = 1


def handle_beacon(pkt):
    # Filter beacon frames
    # 802.11 specifies management frames as type 0 and beacon frames as subtype 8
    if pkt.haslayer(Dot11Beacon) and pkt[Dot11].type == 0 and pkt[Dot11].subtype == 8:
        bssid = pkt[Dot11].addr3
        ssid = pkt[Dot11Elt].info.decode()
        print(f'BSSID: {bssid} SSID: {ssid}')


print('Starting channel change thread')
channel_thread = threading.Thread(target=change_channel, args=(START_CHANNEL, INTERFACE_NAME))
channel_thread.start()

print('Sniffing...')
sniff(iface=INTERFACE_NAME, prn=handle_beacon, store=0)