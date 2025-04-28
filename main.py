import threading
import gui
from network_scanner import NetworkScanner
from scapy.utils import *

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


def save_capture(ap):
    """Save captured EAPOL messages and beacon frames to a .pcap file"""

    writer = PcapWriter('captures/handshake.pcap', append=True)
    for _, packet in ap.eapol_messages.items():
        writer.write(packet)
    writer.write(ap.beacon)


scanner = NetworkScanner(INTERFACE_NAME, CHANNEL_TABLE, START_CHANNEL)

print('Starting GUI thread')
gui_thread = threading.Thread(target=gui.start_gui, args=(scanner, save_capture,))
gui_thread.start()

print('Starting sniffing thread')
sniff_thread = threading.Thread(target=scanner.start_sniffing)
sniff_thread.start()

print('Starting channel switching thread')
chan_thread = threading.Thread(target=scanner.start_channel_hopping)
chan_thread.start()
