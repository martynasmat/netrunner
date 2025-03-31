from scapy.all import *
from scapy.layers.dot11 import *
import threading
from change_channel import change_channel
import gui

INTERFACE_NAME = 'wlan0mon'
START_CHANNEL = 1

class AccessPoint():
    
    def __init__(self, ssid, bssid):
        self.ssid = ssid
        self.bssid = bssid
        # List of clients (possibly) connected to the AP
        self.clients = []


def handle_beacon(pkt):
    bssid = pkt[Dot11].addr3
    ssid = pkt[Dot11Elt].info.decode()

    if bssid not in ap_bssids:
        ap_bssids.add(bssid)
        ap = AccessPoint(ssid, bssid)
        access_points.append(ap)
        ap_map[bssid] = ap


def get_aps():
    return access_points


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


def start_sniffing():
    sniff(iface=INTERFACE_NAME, prn=handle_packet, store=0)


access_points = []
# Access point MAC addresses
ap_bssids = set()
# BSSID:AccessPoint
ap_map = {}

print('Starting GUI thread')
gui_thread = threading.Thread(target=gui.start_gui, args=(get_aps,))
gui_thread.start()

print('Starting sniffing thread')
sniff_thread = threading.Thread(target=start_sniffing)
sniff_thread.start()

print('Starting channel switching thread')
channel_thread = threading.Thread(target=change_channel, args=(START_CHANNEL, INTERFACE_NAME))
channel_thread.start()