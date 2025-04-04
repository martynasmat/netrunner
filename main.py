from scapy.all import *
from scapy.layers.dot11 import *
import threading
from change_channel import change_channel
import gui

INTERFACE_NAME = 'wlan0mon'
START_CHANNEL = 1

class AccessPoint():
    
    def __init__(self, ssid, bssid, signal_strength=None):
        self.ssid = ssid
        self.bssid = bssid
        # List of clients (possibly) connected to the AP
        self.clients = []
        self.signal_strength = signal_strength

    def update_signal_strength(self, dbm):
        self.signal_strength = dbm

    def add_client(self, client):
        self.clients.append(client)


def handle_beacon(pkt):
    bssid = pkt[Dot11].addr3
    ssid = pkt[Dot11Elt].info.decode()
    signal_strength = pkt[RadioTap].dBm_AntSignal

    if bssid not in ap_bssids:
        ap_bssids.add(bssid)
        ap = AccessPoint(ssid, bssid, signal_strength)
        access_points.append(ap)
        bssid_map[bssid] = ap
        ssid_map[ssid] = ap
    else:
        bssid_map[bssid].update_signal_strength(signal_strength)


def get_aps():
    return access_points


def handle_packet(pkt):
    # Handle beacon frames
    if pkt.haslayer(Dot11Beacon) and pkt[Dot11].type == 0 and pkt[Dot11].subtype == 8:
        handle_beacon(pkt)

    # Handle probe requests
    elif pkt.haslayer(Dot11ProbeReq) and pkt[Dot11].type == 0 and pkt[Dot11].subtype == 4:
        ssid = pkt[Dot11ProbeReq].info.decode()
        if ssid:
            ap = ssid_map[ssid]
            if ssid not in ap.clients: 
                ap.add_client(pkt[Dot11].addr2)

    # Handle association requests
    elif pkt.haslayer(Dot11AssoReq) and pkt[Dot11].type == 0 and pkt[Dot11].subtype == 0:
        print(pkt)
        source = pkt[Dot11].addr2
        bssid = pkt[Dot11].addr1
        if bssid in bssid_map and source not in bssid_map[bssid].clients:
            bssid_map[bssid].add_client(source)

    # Handle data frames
    elif pkt.haslayer(Dot11) and pkt[Dot11].type == 2:
        match pkt[Dot11].subtype:
            # Data frame
            case 0:  
                source = pkt[Dot11].addr2
                destination = pkt[Dot11].addr1
                process_client_data_frame(source, destination)

            # Null data frame
            case 4:
                source = pkt[Dot11].addr2
                destination = pkt[Dot11].addr3
                process_client_data_frame(source, destination)

            # QoS data frame
            case 8:
                source = pkt[Dot11].addr2
                destination = pkt[Dot11].addr3
                process_client_data_frame(source, destination)


def process_client_data_frame(src, dest):
    if dest in bssid_map.keys() and dest != 'ff:ff:ff:ff:ff:ff':
            if src not in bssid_map[dest].clients:
                bssid_map[dest].add_client(src)


def start_sniffing():
    sniff(iface=INTERFACE_NAME, prn=handle_packet, store=False)


access_points = []
# Access point MAC addresses
ap_bssids = set()
# BSSID:AccessPoint
bssid_map = {}
# SSID:AccessPoint
ssid_map = {}

print('Starting GUI thread')
gui_thread = threading.Thread(target=gui.start_gui, args=(get_aps,))
gui_thread.start()

print('Starting sniffing thread')
sniff_thread = threading.Thread(target=start_sniffing)
sniff_thread.start()

print('Starting channel switching thread')
channel_thread = threading.Thread(target=change_channel, args=(START_CHANNEL, INTERFACE_NAME))
channel_thread.start()