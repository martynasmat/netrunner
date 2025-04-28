from scapy.all import *

def start_sniffing():
    sniff(iface=INTERFACE_NAME, prn=handle_packet, store=False, stop_filter=lambda x: stop_sniffing.is_set())


def create_sniff_thread():
    return threading.Thread(target=start_sniffing)