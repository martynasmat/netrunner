import threading
import gui

from network_utilities import *

# TODO:
# Support other types of frames to identify clients
# Show number of packets sent
# Show security standard

# Interface has to be in monitor modeauto
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

scanner = NetworkScanner(INTERFACE_NAME, CHANNEL_TABLE, START_CHANNEL)

# GUI
gui_thread = threading.Thread(target=gui.start_gui, args=(scanner,))
gui_thread.start()

# Sniffing
sniff_thread = threading.Thread(target=scanner.start_sniffing)
sniff_thread.start()

# Change channels
chan_thread = threading.Thread(target=scanner.start_channel_hopping)
chan_thread.start()

gui_thread.join()
sniff_thread.join()
chan_thread.join()
