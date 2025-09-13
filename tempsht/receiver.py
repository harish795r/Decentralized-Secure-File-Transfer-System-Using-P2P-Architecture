import socket
import time
import tkinter as tk

CHUNK_SIZE = 4096

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
