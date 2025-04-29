class AccessPoint():
    """Represents an access point, stores relevant information for deauthentication and packet capture"""

    def __init__(
            self,
            ssid: str,
            bssid: str,
            signal_strength: int = 0,
            channel: int = 1,
            beacon=None):
        self.ssid = ssid
        # MAC address
        self.bssid = bssid
        # List of clients (possibly) connected to the AP
        self.clients = []
        self.signal_strength = signal_strength
        self.channel = channel
        self.eapol_messages = {
            1: None,
            2: None,
            3: None,
            4: None,
        }
        self.beacon = beacon

    def update_signal_strength(self, dbm: int):
        """Update signal strength value"""
        self.signal_strength = dbm

    def update_channel(self, chan: int):
        """Update channel value"""
        self.channel = chan

    def add_client(self, client: str):
        """Append new client"""
        self.clients.append(client)
