class AccessPoint():
    
    def __init__(self, ssid, bssid, signal_strength=0, channel=1, beacon=None):
        self.ssid = ssid
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

    def update_signal_strength(self, dbm):
        """Update signal strength value"""
        self.signal_strength = dbm

    def add_client(self, client):
        """Append new client"""
        self.clients.append(client)