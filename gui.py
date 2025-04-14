import curses

def start_gui(update_callback, stop_event):

    def draw_menu(stdscr, update_callback, stop_event):
        curses.curs_set(0)
        stdscr.nodelay(1)
        stdscr.timeout(100)  # Refresh rate (milliseconds)
        last_row = 2
        
        ap_list = []

        while True:
            stdscr.clear()
            stdscr.addstr(0, 0, "Netrunner - WiFi Scanner (WIP)", curses.A_BOLD)
            stdscr.addstr(1, 0, "Press 'q' to exit")
        
            # Refresh AP list
            ap_list[:] = update_callback()  # Call the scanner function

            # Display APs
            for idx, ap in enumerate(ap_list, start=3):
                line = f"{idx-2}. {ap.ssid} ({ap.bssid}) {ap.signal_strength} dBm | Clients: {len(ap.clients)}"
                stdscr.addstr(idx, 0, line)  # truncate if needed
                last_row = idx
                if idx >= stdscr.getmaxyx()[0]:
                    break

            stdscr.addstr(last_row+2, 0, "Press Enter to stop scanning networks")


            # Handle user input
            key = stdscr.getch()
            if key == ord('q'):
                break

            elif key == ord('\n'):
                stop_event.set()

            stdscr.refresh()

    curses.wrapper(draw_menu, update_callback, stop_event)
