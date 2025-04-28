from scapy.layers.dot11 import *
from scapy.layers.eap import *

def handle_packet(pkt):
    """Handle different types of 802.11 frames"""

    # Handle beacon frames
    if pkt.haslayer(Dot11Beacon) and pkt[Dot11].type == 0 and pkt[Dot11].subtype == 8:
        handle_beacon(pkt)

    # Handle EAPOL frame (handshake)
    elif pkt.haslayer(EAPOL):
        handle_eapol(pkt)

    # Handle probe requests
    elif pkt.haslayer(Dot11ProbeReq) and pkt[Dot11].type == 0 and pkt[Dot11].subtype == 4:
        ssid = pkt[Dot11ProbeReq].info.decode()
        if ssid:
            ap = ssid_map.get(ssid)
            if ap and pkt[Dot11].addr2 not in ap.clients: 
                ap.add_client(pkt[Dot11].addr2)

    # Handle association requests
    elif pkt.haslayer(Dot11AssoReq) and pkt[Dot11].type == 0 and pkt[Dot11].subtype == 0:
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


def handle_beacon(pkt):
    """Handle beacon frames"""

    bssid = pkt[Dot11].addr3
    ssid = pkt[Dot11Elt].info.decode()
    signal_strength = pkt[RadioTap].dBm_AntSignal
    channel = CHANNEL_TABLE[pkt[RadioTap].Channel]

    # Some APs have hidden SSIDs
    if not ssid:
        ssid = 'HIDDEN SSID'

    if bssid not in ap_bssids:
        ap_bssids.add(bssid)
        ap = AccessPoint(ssid, bssid, signal_strength, channel, pkt)
        access_points.append(ap)
        bssid_map[bssid] = ap
        ssid_map[ssid] = ap
    else:
        bssid_map[bssid].update_signal_strength(signal_strength)


def handle_eapol(pkt):
    """Process EAPOL packet, save key message type"""

    msg_type = pkt[EAPOL_KEY].guess_key_number()
    if pkt[Dot11].addr1 in bssid_map:
        bssid_map[pkt[Dot11].addr1].eapol_messages[msg_type] = pkt
    elif pkt[Dot11].addr2 in bssid_map:
        bssid_map[pkt[Dot11].addr2].eapol_messages[msg_type] = pkt
    elif pkt[Dot11].addr3 in bssid_map:
        bssid_map[pkt[Dot11].addr3].eapol_messages[msg_type] = pkt


def process_client_data_frame(src, dest):
    if dest in bssid_map.keys() and dest != 'ff:ff:ff:ff:ff:ff':
            if src not in bssid_map[dest].clients:
                bssid_map[dest].add_client(src)