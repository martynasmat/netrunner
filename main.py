from scapy.all import *
from scapy.layers.dot11 import *
import threading
import os

INTERFACE_NAME = 'wlan0mon'
START_CHANNEL = 1

def change_channel():
    # Periodically change channels to discover all available networks
    channel = START_CHANNEL

    while True:
        print(f'Switched channel to channel {channel}')
        os.system(f'sudo iwconfig {INTERFACE_NAME} channel {channel}')
        # 2.4GHz WiFi supports 14 channels according to https://en.wikipedia.org/wiki/List_of_WLAN_channels
        channel = channel % 14 + 1
        time.sleep(2)


def handle_beacon(pkt):

    # Filter beacon frames
    # 802.11 specifies management frames as type 0 and beacon frames as subtype 8
    if pkt.haslayer(Dot11Beacon) and pkt[Dot11].type == 0 and pkt[Dot11].subtype == 8:
        bssid = pkt[Dot11].addr3
        ssid = pkt[Dot11Elt].info.decode()
        print(f'BSSID: {bssid} SSID: {ssid}')


print('Starting channel change thread')
channel_thread = threading.Thread(target=change_channel)
channel_thread.start()

print('Sniffing...')
sniff(iface=INTERFACE_NAME, prn=handle_beacon, store=0)