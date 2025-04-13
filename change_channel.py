import os
import time

SWITCH_TIME = 0.25

def change_channel(channel_arg, interface):
    # Periodically change channels to discover all available networks
    channel = channel_arg

    while True:
        print(f'Switched channel to channel {channel}')
        os.system(f'sudo iwconfig {interface} channel {channel}')
        # 2.4GHz WiFi supports 14 channels according to https://en.wikipedia.org/wiki/List_of_WLAN_channels
        channel = channel % 14 + 1
        time.sleep(SWITCH_TIME)