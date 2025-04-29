import os
import time
import threading

SWITCH_TIME = 0.25


def change_channel(
        channel_arg: int,
        interface: str,
        stop_event: threading.Event) -> None:
    # Periodically change channels to discover all available networks
    channel = channel_arg

    while not stop_event.is_set():
        os.system(f'sudo iwconfig {interface} channel {channel}')
        # 2.4GHz WiFi supports 14 channels according to
        # https://en.wikipedia.org/wiki/List_of_WLAN_channels
        channel = channel % 14 + 1
        time.sleep(SWITCH_TIME)


def lock_channel(channel: int, interface: str) -> None:
    # Locks to one channel
    os.system(f'sudo iwconfig {interface} channel {channel}')
