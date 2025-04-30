# Netrunner (WIP)

## 🚨 DISCLAIMER

This tool is for educational purposes only and must NOT be used on networks without permission. Use only on networks you own or have explicit authorization to test.

## About

Netrunner is a Python-based tool for Wi-Fi reconnaissance and WPA/WPA2 handshake capture. It provides a simple terminal interface to scan for nearby access points, deauthenticate connected clients, and save their EAPOL handshakes for offline analysis.

## Overview

Netrunner automates three main steps:

1. Scanning: Hops across 2.4 GHz channels to discover available access points (APs).

2. Deauthentication: Sends IEEE 802.11 deauthentication frames to connected clients, forcing them to reconnect.

3. Handshake Capture: Listens for the four-message EAPOL handshake and writes it, along with the beacon frame, to a timestamped PCAP file.

All actions run in parallel threads, and you control them through a curses-based UI.

## Features:

- **Channel Hopping:** Automatically cycles through channels to find APs.  
- **Client Detection:** Tracks clients using beacon, probe, association, and data frames.  
- **Deauth Attack:** Crafts and sends deauthentication frames to each client.  
- **Handshake Logging:** Waits for all four EAPOL messages before saving.  
- **Terminal UI:** Select targets, monitor progress, and save captures without leaving the terminal.

## Requirements

- **OS:** Linux with `iwconfig` (e.g., Ubuntu, Debian, Kali).  
- **Python:** 3.7 or later.  
- **Dependencies:** Specified in `requirements.txt`, including:
  - Scapy  
  - curses, threading, subprocess, pathlib, time (standard library)

## Usage

Before running, enable monitor mode on your network interface with

```sudo airmon-ng start [INTERFACE NAME]```

Run:

```sudo python main.py```

1. The UI will list detected APs with SSID, BSSID, signal strength, client count, and channel.

2. Press Enter to stop scanning and pick an AP by number.

3. The tool will start sending deauth frames and show packet count.

4. After deauthentication, it will lock to the AP’s channel and capture EAPOL handshakes.

5. Once all four messages are received, press Enter to save the handshake.

### Demonstration
https://github.com/user-attachments/assets/fc34e4c6-e775-4287-af90-5c741b6c86f6

## Project Structure

```
netrunner/
├── access_point.py         # Stores AP info and EAPOL messages
├── capture_manager.py      # Saves packets and beacons to PCAP
├── change_channel.py       # Handles channel hopping and locking
├── gui.py                  # Curses-based user interface
├── main.py                 # Entry point and thread setup
└── network_utilities.py    # Responsible for sniffing, deauthentication, and capture
```

