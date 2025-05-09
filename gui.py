import curses
import threading

from change_channel import *
from network_utilities import *


def start_gui(scanner: NetworkScanner) -> None:

    def draw_menu(stdscr) -> None:
        curses.curs_set(0)
        stdscr.nodelay(1)
        stdscr.timeout(100)  # Refresh rate (milliseconds)
        scanning_menu(stdscr)

    def scanning_menu(stdscr) -> None:
        last_row = 2
        ap_list = []
        loop = True

        while loop:
            stdscr.clear()
            stdscr.addstr(
                0,
                0,
                "Netrunner - WiFi Scanner (WIP)",
                curses.A_BOLD)
            stdscr.addstr(1, 0, "Press 'q' to exit")

            # Refresh AP list
            ap_list[:] = scanner.access_points

            # Display APs
            for idx, ap in enumerate(ap_list, start=3):
                line = f"{idx-2:3}. {ap.ssid:25
                    } | MAC: ({ap.bssid}) | {
                    ap.signal_strength} dBm | Clients: {
                    len(ap.clients)} | Channel: {ap.channel}"
                stdscr.addstr(idx, 0, line)  # truncate if needed
                last_row = idx
                if idx >= stdscr.getmaxyx()[0]:
                    break

            stdscr.addstr(
                last_row + 2,
                0,
                "Press Enter to stop scanning networks")

            # Handle user input
            key = stdscr.getch()
            if key == ord('q'):
                scanner.stop_all()
                loop = False

            elif key == ord('\n'):
                scanner.stop_sniff.set()
                scanner.stop_changing_channel.set()
                stdscr.nodelay(0)  # Turn blocking input back on for user input
                stdscr.timeout(-1)
                input_loop = True

                # Show cursor to input number
                curses.curs_set(1)
                curses.echo()
                while input_loop:
                    stdscr.addstr(min(stdscr.getmaxyx()[0] - 1, len(ap_list) + 5), 0, "AP to deauth: ")
                    choice = str(stdscr.getstr().decode().strip())

                    # Input validation
                    if choice.isnumeric():
                        index = int(choice) - 1
                        if 0 <= index < len(ap_list):
                            if len(ap_list[index].clients):
                                scanner.select_ap(ap_list[index])
                                input_loop = False

                    # Clear last line
                    y = stdscr.getyx()[0]
                    stdscr.move(y-1, 0)
                    stdscr.clrtoeol()

                curses.noecho()
                curses.curs_set(0)
                stdscr.nodelay(1)
                stdscr.timeout(100)
                stdscr.clear()
                loop = False
                deauth_menu(stdscr)

            stdscr.refresh()

    def deauth_menu(stdscr) -> None:
        loop = True
        stdscr.timeout(50)
        period = 0
        stdscr.clear()

        scanner.create_deauther()
        deauth_thread = threading.Thread(target=scanner.deauther.deauth)
        deauth_thread.start()

        while loop:
            period = period % 4
            stdscr.addstr(0, 0, "Netrunner - WiFi Tool (WIP)", curses.A_BOLD)
            stdscr.addstr(2, 0, "Press 'q' to exit")
            stdscr.addstr(3, 0, f"Deauthing {scanner.selected_ap.ssid}({scanner.selected_ap.bssid}){period * '.'}")
            stdscr.addstr(4, 0, f"Packet sent [{scanner.deauther.packets_sent}/{scanner.deauther.packet_count}]")
            stdscr.addstr(7, 0, f"Please wait for deauthentication to finish")

            BAR_WIDTH = 40

            # Packet count
            sent = scanner.deauther.packets_sent
            total = scanner.deauther.packet_count
            stdscr.addstr(5, 0, f"Packets sent: {sent}/{total}")

            # Progress bar
            frac = sent / total
            filled = int(frac * BAR_WIDTH)
            bar = "#" * filled + "-" * (BAR_WIDTH - filled)
            stdscr.addstr(6, 0, f"[{bar}] {int(frac * 100):3d}%")

            key = stdscr.getch()
            if key == ord('q'):
                deauth_thread.join()
                scanner.stop_all()
                loop = False

            if scanner.deauther.packets_sent >= scanner.deauther.packet_count:
                loop = False
                handshake_menu(stdscr)

            period += 1
            stdscr.clear()
            stdscr.refresh()

    def handshake_menu(stdscr) -> None:
        loop = True
        stdscr.clear()
        stdscr.timeout(500)
        scanner.lock_chnl()
        scanner.stop_sniff.clear()

        # Start sniffing again, filter EAP packets
        sniff_thread = threading.Thread(
            target=scanner.start_sniffing, args=(
                'ether proto 0x888e',))
        sniff_thread.start()

        while loop:
            stdscr.addstr(0, 0, "Netrunner - WiFi Tool (WIP)", curses.A_BOLD)
            stdscr.addstr(2, 0, "Press 'q' to exit")
            stdscr.addstr(3, 0, f"Press Enter to save captured packets")
            stdscr.addstr(4, 0, f"Press 'p' to retry deauthentication")
            stdscr.addstr(
                5, 0, f"""{
                    scanner.selected_ap.ssid} ({
                    scanner.selected_ap.bssid}) EAPOL messages captured:""")
            i = 0
            for key, pkt in scanner.selected_ap.eapol_messages.items():
                if pkt:
                    i += 1
                    stdscr.addstr(i + 6, 0, f"Message type: {key}")

            key = stdscr.getch()
            if key == ord('q'):
                sniff_thread.join()
                scanner.stop_all()
                loop = False
            elif key == ord('\n'):
                scanner.stop_sniff.set()
                sniff_thread.join()
                filename = scanner.capture_manager.save_capture()
                saved_menu(stdscr, filename)
                loop = False
            elif key == ord('p'):
                scanner.stop_sniff.set()
                sniff_thread.join()
                loop = False
                deauth_menu(stdscr)

            stdscr.clear()
            stdscr.refresh()

    def saved_menu(stdscr, filename: str) -> None:
        loop = True
        stdscr.clear()
        stdscr.timeout(500)
        stdscr.addstr(0, 0, "Netrunner - WiFi Tool (WIP)", curses.A_BOLD)
        stdscr.addstr(2, 0, f"File succesfully saved - {filename}")
        stdscr.addstr(4, 0, "Press any key to exit")

        while loop:
            key = stdscr.getch()
            if key != -1:
                scanner.stop_all()
                loop = False

    curses.wrapper(draw_menu)
