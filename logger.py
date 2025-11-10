import time
import threading
import tkinter as tk

LOG_MAX_LINES = 1000

class Logger:
    def __init__(self, text_widget: tk.Text):
        self.text = text_widget
        self.lock = threading.Lock()

    def log(self, msg: str):
        t = time.strftime("%H:%M:%S")
        line = f"[{t}] {msg}\n"
        with self.lock:
            self.text.insert(tk.END, line)
            # keep log size in limit
            lines = int(self.text.index('end-1c').split('.')[0])
            if lines > LOG_MAX_LINES:
                self.text.delete('1.0', '2.0')
            self.text.see(tk.END)
