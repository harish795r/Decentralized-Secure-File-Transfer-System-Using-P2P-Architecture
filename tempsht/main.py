import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
from utils import local_ip
from logger import Logger
from sender import Sender
from receiver import Receiver

TCP_PORT = 5000

class App:
    def __init__(self, root):
        self.root = root
        root.title("P2P File Transfer (Manual IP)")
        root.geometry("800x600")

        top = tk.Frame(root)
        top.pack(fill=tk.X, padx=8, pady=6)
        tk.Label(top, text="Decentralized File Transfer", font=("Segoe UI", 14, "bold")).pack(side=tk.LEFT)
        self.host_label = tk.Label(top, text=f"Host: {local_ip()}  Port: {TCP_PORT}")
        self.host_label.pack(side=tk.RIGHT)

        mid = tk.Frame(root)
        mid.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        # Send Panel
        send_frame = tk.LabelFrame(mid, text="Send", padx=8, pady=8)
        send_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=6, pady=6)
        self.send_file_label = tk.Label(send_frame, text="No file selected")
        self.send_file_label.pack(fill=tk.X, pady=(0,6))
        tk.Button(send_frame, text="Select File", command=self.select_file).pack(fill=tk.X)
        tk.Button(send_frame, text="Proceed (Start Sending)", command=self.proceed_send).pack(fill=tk.X, pady=(6,0))
        tk.Button(send_frame, text="Stop Sending", command=self.stop_send).pack(fill=tk.X, pady=(6,0))
        self.send_status = tk.Label(send_frame, text="Idle", fg="green")
        self.send_status.pack(pady=(6,0))

        # Receive Panel
        recv_frame = tk.LabelFrame(mid, text="Receive", padx=8, pady=8)
        recv_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=6, pady=6)

        ip_row = tk.Frame(recv_frame)
        ip_row.pack(fill=tk.X)
        tk.Label(ip_row, text="Sender IP:").pack(side=tk.LEFT)
        self.ip_entry = tk.Entry(ip_row)
        self.ip_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(6,0))
        tk.Label(ip_row, text="Port:").pack(side=tk.LEFT, padx=(8,0))
        self.port_entry = tk.Entry(ip_row, width=6)
        self.port_entry.insert(0, str(TCP_PORT))
        self.port_entry.pack(side=tk.LEFT)

        tk.Button(recv_frame, text="Get File Info", command=self.get_file_info).pack(fill=tk.X, pady=(6,0))
        self.incoming_info_label = tk.Label(recv_frame, text="No info")
        self.incoming_info_label.pack(fill=tk.X, pady=(6,0))
        tk.Button(recv_frame, text="Proceed (Download)", command=self.proceed_receive).pack(fill=tk.X, pady=(6,0))

        self.recv_status = tk.Label(recv_frame, text="Idle", fg="green")
        self.recv_status.pack(pady=(6,0))
        self.progress = ttk.Progressbar(recv_frame, length=200)
        self.progress.pack(fill=tk.X, pady=(6,0))
        self.speed_label = tk.Label(recv_frame, text="")
        self.speed_label.pack()

        # History
        history_frame = tk.LabelFrame(root, text="Transfer History")
        history_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)
        self.history_table = ttk.Treeview(history_frame, columns=("Time","File","Size","Peer"), show="headings")
        for col in ("Time","File","Size","Peer"):
            self.history_table.heading(col, text=col)
        self.history_table.pack(fill=tk.BOTH, expand=True)

        # Logs
        log_frame = tk.LabelFrame(root, text="Logs")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)
        self.log_text = tk.Text(log_frame, height=8, wrap=tk.NONE)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        tk.Button(log_frame, text="Clear Logs", command=lambda: self.log_text.delete("1.0", tk.END)).pack()
        self.logger = Logger(self.log_text)

        self.sender = Sender(self.logger, self.send_status)
        self.receiver = Receiver(self.logger, self.recv_status, self.progress, self.speed_label)
        self.selected_file_path = None

    def select_file(self):
        path = filedialog.askopenfilename()
        if not path: return
        self.selected_file_path = path
        self.send_file_label.config(text=path.split("/")[-1])
        self.sender.set_file(path)

    def proceed_send(self):
        if not self.selected_file_path:
            messagebox.showwarning("No File", "Please select a file to send first.")
            return
        threading.Thread(target=self.sender.start, daemon=True).start()

    def stop_send(self):
        self.sender.stop()

    def get_file_info(self):
        ip = self.ip_entry.get().strip()
        if not ip: return
        try:
            port = int(self.port_entry.get().strip())
        except: return

        def worker():
            res = self.receiver.get_header(ip, port)
            if res:
                filename, filesize = res
                self.incoming_info_label.config(text=f"Sender file: {filename} ({filesize} bytes)")
            else:
                self.incoming_info_label.config(text="Failed to get info.")
        threading.Thread(target=worker, daemon=True).start()

    def proceed_receive(self):
        ip = self.ip_entry.get().strip()
        if not ip: return
        try:
            port = int(self.port_entry.get().strip())
        except: return

        def ask_save(default_name):
            return filedialog.asksaveasfilename(initialfile=default_name)

        def worker():
            success = self.receiver.download(ip, port, ask_save, self.history_table)
            if success:
                messagebox.showinfo("Download", "File downloaded successfully.")
            else:
                messagebox.showerror("Download", "File download failed.")
        threading.Thread(target=worker, daemon=True).start()

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
