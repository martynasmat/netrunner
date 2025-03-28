from scapy.all import *
from scapy.layers.dot11 import *
import threading
from change_channel import change_channel

INTERFACE_NAME = 'wlan0mon'
START_CHANNEL = 1

def handle_beacon(pkt):
    bssid = pkt[Dot11].addr3
    ssid = pkt[Dot11Elt].info.decode()
    print(f'BSSID: {bssid} SSID: {ssid}')


def handle_packet(pkt):
    # Handle beacon frames
    if pkt.haslayer(Dot11Beacon) and pkt[Dot11].type == 0 and pkt[Dot11].subtype == 8:
        handle_beacon(pkt)

    # Handle data frames
    if pkt.haslayer(Dot11) and pkt[Dot11].type == 2:
        match pkt[Dot11].subtype:
            # Data frame
            case 0:  
                source = pkt[Dot11].addr2
                destination = pkt[Dot11].addr1
                print(f'Data frame / Source {source} / Destination {destination}')

            # Null data frame
            case 4:
                source = pkt[Dot11].addr2
                destination = pkt[Dot11].addr3
                print(f'Null data frame / Source {source} / Destination {destination}')

            # QoS data frame
            case 8:
                source = pkt[Dot11].addr2
                destination = pkt[Dot11].addr3
                print(f'QoS data frame / Source {source} / Destination {destination}')
        
        print(pkt)
        print(pkt.subtype)
        print(pkt[Dot11].addr2)
        print(pkt[Dot11].addr3)


print('Starting channel change thread')
channel_thread = threading.Thread(target=change_channel, args=(START_CHANNEL, INTERFACE_NAME))
channel_thread.start()

print('Sniffing...')
sniff(iface=INTERFACE_NAME, prn=handle_packet, store=0)