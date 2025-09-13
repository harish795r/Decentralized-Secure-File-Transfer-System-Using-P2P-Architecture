# main.py (Improved, no extra modules)
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import socket
import threading
import os
import time

TCP_PORT = 5000
CHUNK_SIZE = 4096
LOG_MAX_LINES = 1000

def local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        try:
            s.close()
        except:
            pass
    return ip

# ---------------- Logger ----------------
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

# ---------------- Sender ----------------
class Sender:
    def __init__(self, logger, status_label):
        self.logger = logger
        self.status_label = status_label
        self.tcp_thread = None
        self.stop_event = threading.Event()
        self.filepath = None
        self.filesize = 0

    def set_file(self, path):
        self.filepath = path
        self.filesize = os.path.getsize(path)
        self.logger.log(f"File set for sending: {path} ({self.filesize} bytes)")

    def start(self, bind_ip="0.0.0.0", tcp_port=TCP_PORT):
        if not self.filepath:
            self.logger.log("No file selected to send.")
            return False
        self.stop_event.clear()
        self.tcp_thread = threading.Thread(target=self._tcp_server,
                                           args=(bind_ip, tcp_port),
                                           daemon=True)
        self.tcp_thread.start()
        self.logger.log("Sender TCP server started.")
        self.set_status("Sending", "blue")
        return True

    def stop(self):
        self.stop_event.set()
        self.set_status("Idle", "green")
        self.logger.log("Sender stopping...")

    def set_status(self, text, color):
        self.status_label.config(text=text, fg=color)

    def _tcp_server(self, bind_ip, tcp_port):
        serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            serv.bind((bind_ip, tcp_port))
            serv.listen(5)
        except Exception as e:
            self.logger.log(f"TCP bind/listen failed: {e}")
            serv.close()
            return

        self.logger.log(f"TCP server listening on {bind_ip}:{tcp_port}")
        serv.settimeout(1.0)
        try:
            while not self.stop_event.is_set():
                try:
                    conn, addr = serv.accept()
                except socket.timeout:
                    continue
                if conn:
                    self.logger.log(f"Client connected: {addr}")
                    try:
                        header = f"{os.path.basename(self.filepath)}|{self.filesize}".encode()
                        conn.sendall(header + b"\n")
                        with open(self.filepath, 'rb') as f:
                            sent = 0
                            while True:
                                chunk = f.read(CHUNK_SIZE)
                                if not chunk:
                                    break
                                conn.sendall(chunk)
                                sent += len(chunk)
                        self.logger.log(f"File sent to {addr[0]} ({sent} bytes).")
                        self.set_status("Done", "green")
                    except Exception as e:
                        self.logger.log(f"Error during file send: {e}")
                        self.set_status("Failed", "red")
                    finally:
                        conn.close()
        finally:
            serv.close()
            self.logger.log("TCP server stopped.")

# ---------------- Receiver ----------------
class Receiver:
    def __init__(self, logger, status_label, progress, speed_label):
        self.logger = logger
        self.status_label = status_label
        self.progress = progress
        self.speed_label = speed_label
        self.cached_header = None

    def set_status(self, text, color):
        self.status_label.config(text=text, fg=color)

    def get_header(self, ip, port):
        self.logger.log(f"Querying header from {ip}:{port} ...")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(6.0)
                s.connect((ip, port))
                header = b""
                while not header.endswith(b"\n"):
                    part = s.recv(1)
                    if not part:
                        break
                    header += part
                filename, filesize = header.decode().strip().split("|")
                filesize = int(filesize)
                self.cached_header = (filename, filesize)
                self.logger.log(f"Header received: {filename} ({filesize} bytes)")
                return filename, filesize
        except Exception as e:
            self.logger.log(f"Failed to get header: {e}")
            return None

    def download(self, ip, port, save_path_callback, history_table):
        if not self.cached_header:
            self.logger.log("No header cached; call get_header first.")
            return False
        filename, filesize = self.cached_header
        self.logger.log(f"Starting download from {ip}:{port} -> {filename} ({filesize} bytes)")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10.0)
                s.connect((ip, port))
                # read header again
                header = b""
                while not header.endswith(b"\n"):
                    part = s.recv(1)
                    if not part:
                        raise RuntimeError("Connection closed")
                    header += part
                save_path = save_path_callback(f"received_{filename}")
                if not save_path:
                    self.logger.log("Save dialog canceled by user.")
                    return False

                received = 0
                start_time = time.time()
                self.set_status("Receiving", "orange")
                self.progress["maximum"] = filesize

                with open(save_path, "wb") as f:
                    while received < filesize:
                        chunk = s.recv(min(CHUNK_SIZE, filesize - received))
                        if not chunk:
                            break
                        f.write(chunk)
                        received += len(chunk)

                        # update progress
                        self.progress["value"] = received
                        elapsed = time.time() - start_time
                        speed = (received / 1024) / elapsed if elapsed > 0 else 0
                        remaining = (filesize - received) / 1024 / speed if speed > 0 else 0
                        self.speed_label.config(
                            text=f"{speed:.1f} KB/s, ETA {remaining:.1f}s"
                        )
                        self.progress.update_idletasks()

                if received == filesize:
                    self.logger.log(f"Download complete: {save_path} ({received} bytes)")
                    self.set_status("Done", "green")
                    history_table.insert("", tk.END, values=(
                        time.strftime("%H:%M:%S"),
                        filename,
                        f"{filesize} B",
                        ip
                    ))
                    return True
                else:
                    self.logger.log(f"Partial download: {received}/{filesize} bytes")
                    self.set_status("Failed", "red")
                    return False
        except Exception as e:
            self.logger.log(f"Download failed: {e}")
            self.set_status("Failed", "red")
            return False

# ---------------- Tkinter App ----------------
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

        # Send panel
        send_frame = tk.LabelFrame(mid, text="Send", padx=8, pady=8)
        send_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=6, pady=6)

        self.send_file_label = tk.Label(send_frame, text="No file selected")
        self.send_file_label.pack(fill=tk.X, pady=(0,6))
        tk.Button(send_frame, text="Select File", command=self.select_file).pack(fill=tk.X)
        tk.Button(send_frame, text="Proceed (Start Sending)", command=self.proceed_send).pack(fill=tk.X, pady=(6,0))
        tk.Button(send_frame, text="Stop Sending", command=self.stop_send).pack(fill=tk.X, pady=(6,0))
        self.send_status = tk.Label(send_frame, text="Idle", fg="green")
        self.send_status.pack(pady=(6,0))

        # Receive panel
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
        self.send_file_label.config(text=os.path.basename(path))
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
