import curses

def start_gui(update_callback):

    def draw_menu(stdscr):
        curses.curs_set(0)
        stdscr.nodelay(1)
        stdscr.timeout(500)  # Refresh rate (milliseconds)
        
        ap_list = []

        while True:
            stdscr.clear()
            stdscr.addstr(0, 0, "Netrunner - WiFi Scanner (WIP)", curses.A_BOLD)
            stdscr.addstr(1, 0, "Press 'q' to exit")

            # Refresh AP list
            ap_list[:] = update_callback()  # Call the scanner function

            # Display APs
            for idx, ap in enumerate(ap_list, start=3):
                stdscr.addstr(idx, 0, f"{idx-2}. {ap.ssid} ({ap.bssid}) {ap.signal_strength} {len(ap.clients)}")

            # Handle user input
            key = stdscr.getch()
            if key == ord("q"):
                break

            stdscr.refresh()

    curses.wrapper(draw_menu)
