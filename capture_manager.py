from scapy.utils import *
from time import localtime, strftime

class CaptureManager():
    """Capture file management"""

    def __init__(self, save_dir):
        self.save_dir = save_dir
        self.ap = None

    def save_capture(self):
        """Save captured EAPOL messages and beacon frames to a .pcap file"""
        filename = f"{self.save_dir}{self.ap.ssid}-{strftime("%Y-%m-%d-%H:%M", localtime())}.pcap"

        writer = PcapWriter(filename, append=True)
        for _, packet in self.ap.eapol_messages.items():
            writer.write(packet)
        writer.write(self.ap.beacon)

        return filename