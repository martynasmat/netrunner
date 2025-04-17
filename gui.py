import curses
from change_channel import *


def start_gui(update_callback, deauth_callback, interface, stop_sniffing, create_sniff_thread, stop_changing_channel, stop_deauthing_event):

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
            ap_list[:] = update_callback()  # Call the scanner function

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
                loop = False

            elif key == ord('\n'):
                stop_sniffing.set()
                stop_changing_channel.set()
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
                        selected_ap = ap_list[index]
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

            stdscr.refresh()
        
        deauth_menu(stdscr, selected_ap)

    def deauth_menu(stdscr, selected):
        loop = True
        stdscr.timeout(500)
        period = 0

        thread = deauth_callback(selected, stop_deauthing_event)
        thread.start()

        while loop:
            period = period % 4
            stdscr.addstr(0, 0, "Netrunner - WiFi Tool (WIP)", curses.A_BOLD)
            stdscr.addstr(1, 0, "Press 'q' to exit")
            stdscr.addstr(3, 0, f"Deauthing {selected.ssid} ({selected.bssid}){period * '.'}")
            stdscr.addstr(4, 0, f"Press Enter to stop deauthing and listen for handshakes")

            key = stdscr.getch()
            if key == ord('q'):
                loop = False
            elif key == ord('\n'):
                stop_deauthing_event.set()
                handshake_menu(stdscr, selected)

            period += 1
            stdscr.erase()
            stdscr.refresh()

    def handshake_menu(stdscr, ap):
        loop = True
        stdscr.clear()
        stdscr.timeout(500)
        lock_channel(ap.channel, interface)
        stop_sniffing.clear()
        thread = create_sniff_thread()
        thread.start()

        while loop:
            stdscr.addstr(0, 0, "Netrunner - WiFi Tool (WIP)", curses.A_BOLD)
            stdscr.addstr(1, 0, "Press 'q' to exit")
            stdscr.addstr(3, 0, f"{ap.ssid} ({ap.bssid}) EAPOL messages captured:")
            i = 0
            for key, pkt in ap.eapol_messages.items():
                if pkt:
                    i += 1
                    stdscr.addstr(i + 4, 0, f"Message type: {key} | ")

            key = stdscr.getch()
            if key == ord('q'):
                loop = False

            stdscr.clear()
            stdscr.refresh()


    curses.wrapper(draw_menu)
