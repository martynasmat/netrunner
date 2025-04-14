import curses

def start_gui(update_callback, stop_event):

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
                line = f"{idx-2:3}. {ap.ssid:25} | MAC: ({ap.bssid}) | {ap.signal_strength} dBm | Clients: {len(ap.clients)}"
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
                stdscr.nodelay(0)  # Turn blocking input back on for user input
                stdscr.timeout(-1)

                # Show cursor to input number
                curses.curs_set(1)
                curses.echo()
                stdscr.addstr(min(stdscr.getmaxyx()[0] - 1, len(ap_list) + 5), 0, "AP #: ")
                try:
                    choice = stdscr.getstr().decode().strip()
                    index = int(choice)
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
        
        deauth_menu(stdscr, selected_ap.ssid)

    def deauth_menu(stdscr, selected):
        loop = True

        while loop:
            stdscr.addstr(1, 0, selected)
            stdscr.refresh()

    curses.wrapper(draw_menu)
