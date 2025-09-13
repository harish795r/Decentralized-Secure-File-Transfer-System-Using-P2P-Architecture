import tkinter as tk
from tkinter import ttk
from ttkbootstrap import Style
import time

class DemoApp:
    def __init__(self, root):
        style = Style("darkly")  # dark theme
        root.title("P2P File Transfer Enhanced")

        # Main PanedWindow (resizable)
        paned = ttk.PanedWindow(root, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # Top panel (status + progress)
        top_frame = ttk.Frame(paned, padding=10)
        paned.add(top_frame, weight=1)

        # Status indicator
        self.status_label = ttk.Label(top_frame, text="Idle", foreground="gray")
        self.status_label.pack(anchor="w")

        # Progress bar + info
        self.progress = ttk.Progressbar(top_frame, length=400, mode="determinate")
        self.progress.pack(pady=6, fill=tk.X)

        self.progress_info = ttk.Label(top_frame, text="Progress: 0% | Speed: 0 KB/s | ETA: --")
        self.progress_info.pack(anchor="w")

        # Transfer history
        columns = ("time", "filename", "size", "role", "peer", "status")
        self.history = ttk.Treeview(top_frame, columns=columns, show="headings", height=5)
        for col in columns:
            self.history.heading(col, text=col.title())
            self.history.column(col, width=100)
        self.history.pack(fill=tk.BOTH, expand=True, pady=8)

        # Bottom panel (logs with clear button)
        bottom_frame = ttk.Frame(paned, padding=10)
        paned.add(bottom_frame, weight=1)

        self.log_text = tk.Text(bottom_frame, height=10)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(bottom_frame, command=self.log_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=scrollbar.set)

        clear_btn = ttk.Button(bottom_frame, text="Clear Logs", command=self.clear_logs)
        clear_btn.pack(pady=5)

        # demo button to simulate a transfer
        ttk.Button(top_frame, text="Simulate Transfer", command=self.simulate_transfer).pack(pady=5)

    def clear_logs(self):
        self.log_text.delete("1.0", tk.END)

    def log(self, msg):
        t = time.strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{t}] {msg}\n")
        self.log_text.see(tk.END)

    def set_status(self, status, color="gray"):
        self.status_label.config(text=status, foreground=color)

    def update_progress(self, percent, speed, eta):
        self.progress["value"] = percent
        self.progress_info.config(text=f"Progress: {percent:.1f}% | Speed: {speed:.1f} KB/s | ETA: {eta:.1f}s")

    def add_history(self, filename, size, role, peer, status):
        t = time.strftime("%H:%M:%S")
        self.history.insert("", tk.END, values=(t, filename, f"{size} bytes", role, peer, status))

    # simulate transfer to show updates
    def simulate_transfer(self):
        self.set_status("Receiving", "blue")
        filename = "demo.txt"
        size = 10240
        peer = "192.168.1.10"
        for i in range(1, 101):
            speed = 50.0
            eta = (100 - i) / (speed / 10)
            self.update_progress(i, speed, eta)
            self.log(f"Receiving... {i}%")
            root.update()
            time.sleep(0.05)
        self.set_status("Done", "green")
        self.add_history(filename, size, "Received", peer, "Success")
        self.log("Transfer complete.")

if __name__ == "__main__":
    root = tk.Tk()
    app = DemoApp(root)
    root.geometry("800x600")
    root.mainloop()
