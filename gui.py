import curses
import threading

from change_channel import *


def start_gui(scanner):

    def draw_menu(stdscr):
        curses.curs_set(0)
        stdscr.nodelay(1)
        stdscr.timeout(100)  # Refresh rate (milliseconds)
        scanning_menu(stdscr)

    def scanning_menu(stdscr):
        last_row = 2
        ap_list = []
        loop = True

        while loop:
            stdscr.clear()
            stdscr.addstr(0, 0, "Netrunner - WiFi Scanner (WIP)", curses.A_BOLD)
            stdscr.addstr(1, 0, "Press 'q' to exit")
        
            # Refresh AP list
            ap_list[:] = scanner.access_points

            # Display APs
            for idx, ap in enumerate(ap_list, start=3):
                line = f"{idx-2:3}. {ap.ssid:25} | MAC: ({ap.bssid}) | {ap.signal_strength} dBm | Clients: {len(ap.clients)} | Channel: {ap.channel}"
                stdscr.addstr(idx, 0, line)  # truncate if needed
                last_row = idx
                if idx >= stdscr.getmaxyx()[0]:
                    break

            stdscr.addstr(last_row+2, 0, "Press Enter to stop scanning networks")


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

                # Show cursor to input number
                curses.curs_set(1)
                curses.echo()
                stdscr.addstr(min(stdscr.getmaxyx()[0] - 1, len(ap_list) + 5), 0, "AP to deauth: ")
                try:
                    choice = stdscr.getstr().decode().strip()
                    index = int(choice) - 1
                    if 0 <= index < len(ap_list):
                        scanner.select_ap(ap_list[index])
                    else:
                        footer = "Invalid selection."
                except Exception:
                    footer = "Error reading input."

                curses.noecho()
                curses.curs_set(0)
                stdscr.nodelay(1)
                stdscr.timeout(100)
                stdscr.clear()
                loop = False
                deauth_menu(stdscr)


            stdscr.refresh()
        

    def deauth_menu(stdscr):
        loop = True
        stdscr.timeout(500)
        period = 0
        stdscr.clear()

        deauth_thread = threading.Thread(target=scanner.deauth)
        deauth_thread.start()

        while loop:
            period = period % 4
            stdscr.addstr(0, 0, "Netrunner - WiFi Tool (WIP)", curses.A_BOLD)
            stdscr.addstr(1, 0, "Press 'q' to exit")
            stdscr.addstr(3, 0, f"Deauthing {scanner.selected_ap.ssid} ({scanner.selected_ap.bssid}){period * '.'}")
            stdscr.addstr(4, 0, f"Packet sent [{scanner.deauth_packet_count}/{scanner.max_packets}]")
            stdscr.addstr(5, 0, f"Please wait for deauthentication to finish")
            key = stdscr.getch()
            if key == ord('q'):
                scanner.stop_all()
                loop = False
            
            if scanner.deauth_packet_count >= scanner.max_packets:
                loop = False
                handshake_menu(stdscr)

            period += 1
            stdscr.clear()
            stdscr.refresh()

    def handshake_menu(stdscr):
        loop = True
        stdscr.clear()
        stdscr.timeout(500)
        scanner.lock_chnl()
        scanner.stop_sniff.clear()

        # Start sniffing again, filter EAP packets
        sniff_thread = threading.Thread(target=scanner.start_sniffing, args=('ether proto 0x888e',))
        sniff_thread.start()

        while loop:
            stdscr.addstr(0, 0, "Netrunner - WiFi Tool (WIP)", curses.A_BOLD)
            stdscr.addstr(2, 0, "Press 'q' to exit")
            stdscr.addstr(3, 0, f"Press Enter to save captured packets")
            stdscr.addstr(4, 0, f"Press 'p' to retry deauthentication")
            stdscr.addstr(5, 0, f"{scanner.selected_ap.ssid} ({scanner.selected_ap.bssid}) EAPOL messages captured:")
            i = 0
            for key, pkt in scanner.selected_ap.eapol_messages.items():
                if pkt:
                    i += 1
                    stdscr.addstr(i + 6, 0, f"Message type: {key}")

            key = stdscr.getch()
            if key == ord('q'):
                scanner.stop_all()
                loop = False
            elif key == ord('\n'):
                scanner.stop_sniff.set()
                filename = scanner.capture_manager.save_capture()
                saved_menu(stdscr, filename)
                loop = False
            elif key == ord('p'):
                scanner.stop_sniff.set()
                loop = False
                deauth_menu(stdscr)

            stdscr.clear()
            stdscr.refresh()

    def saved_menu(stdscr, filename):
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
