import threading

class ThreadManager():

    def __init__(self, gui_func, scanner, save):
        self.gui_thread = threading.Thread(target=gui_func, args=(scanner, save,))
        self.sniff_thread = scanner.create_sniff_thread()
        self.channel_thread = scanner.create_channel_thread()

    def start_threads(self):
        self.gui_thread.start()
        self.sniff_thread.start()
        self.channel_thread.start()
    