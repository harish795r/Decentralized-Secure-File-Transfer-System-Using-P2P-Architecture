import time
import threading
import tkinter as tk
import queue

LOG_MAX_LINES = 1000

class Logger:
    def __init__(self, text_widget: tk.Text):
        self.text = text_widget
        self.lock = threading.Lock()
        self.log_queue = queue.Queue()
        self.text.after(100, self._process_log_queue)

    def log(self, msg: str):
        t = time.strftime("%H:%M:%S")
        line = f"[{t}] {msg}\n"
        self.log_queue.put(line)
    
    def _process_log_queue(self):
        try:
            while True:
                line = self.log_queue.get_nowait()
                with self.lock:
                    self.text.insert(tk.END, line)
                    # keep log size in limit
                    lines = int(self.text.index('end-1c').split('.')[0])
                    if lines > LOG_MAX_LINES:
                        self.text.delete('1.0', '2.0')
                    self.text.see(tk.END)
        except queue.Empty:
            pass
        # Schedule the next queue processing
        self.text.after(100, self._process_log_queue)
