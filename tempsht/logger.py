import tkinter as tk
import threading
import time

LOG_MAX_LINES = 1000

class Logger:
    def __init__(self, text_widget):
        self.text = text_widget
        self.lock = threading.Lock()

    def log(self, msg):
        t = time.strftime("%H:%M:%S")
        line = f"[{t}] {msg}\n"
        with self.lock:
            self.text.insert(tk.END, line)
            lines = int(self.text.index('end-1c').split('.')[0])
            if lines > LOG_MAX_LINES:
                self.text.delete('1.0', '2.0')
            self.text.see(tk.END)
