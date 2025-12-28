import socket
import time
import tkinter as tk
import base64
import threading
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from utils import derive_key

CHUNK_SIZE = 4096

class Receiver:
    def __init__(self, logger, status_label, progress, speed_label):
        self.logger = logger
        self.status_label = status_label
        self.progress = progress
        self.speed_label = speed_label
        self.cached_header = None
        self.paused = False
        self.stop_event = threading.Event()
        self.downloading = False
        self.received_bytes = 0
        self.last_speed = 0
        self.start_time = 0
        self._last_progress_update = 0

    def set_status(self, text, color):
        self.status_label.config(text=text, fg=color)

    def toggle_pause(self):
        self.paused = not self.paused
        state = "Paused" if self.paused else "Resumed"
        self.logger.log(f"Download {state}.")

    def stop_download(self):
        if self.downloading:
            self.stop_event.set()
            self.downloading = False
            self.paused = False
            self.set_status("Stopped", "red")
            self.logger.log("Download stopped by user.")

    def get_header(self, ip, port):
        self.logger.log(f"Querying header from {ip}:{port} ...")
        # Try to connect with retries
        max_retries = 3
        for attempt in range(max_retries):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(15.0)  # Increase timeout to 15 seconds
                    s.connect((ip, port))
                    # Read header more efficiently - up to 1024 bytes should be enough for header
                    header_data = s.recv(1024)
                    if b'\n' in header_data:
                        header = header_data.split(b'\n')[0]
                    else:
                        header = header_data
                    parts = header.decode().strip().split("|")
                    if len(parts) == 2:
                        filename, filesize = parts
                        self.cached_header = (filename, int(filesize), False, None, None)
                    elif len(parts) == 4:
                        filename, filesize, salt_b64, iv_b64 = parts
                        salt = base64.b64decode(salt_b64)
                        iv = base64.b64decode(iv_b64)
                        self.cached_header = (filename, int(filesize), True, salt, iv)
                    
                    # Check if we successfully parsed the header
                    if self.cached_header is not None:
                        self.logger.log(f"Header received: {self.cached_header[0]} ({self.cached_header[1]} bytes)")
                        return self.cached_header[0], self.cached_header[1]
                    else:
                        self.logger.log("Failed to parse header")
                        return None
            except Exception as e:
                self.logger.log(f"Failed to get header from {ip}:{port} (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(1)  # Wait before retrying
        return None

    def download(self, ip, port, save_path_callback, history_table, password=None):
        if not self.cached_header:
            self.logger.log("No header cached; call get_header first.")
            return False

        filename, filesize, encrypted, salt, iv = self.cached_header
        self.logger.log(f"Starting download from {ip}:{port} -> {filename}")
        self.stop_event.clear()
        self.downloading = True
        self.paused = False
        self.received_bytes = 0
        self.start_time = time.time()

        # Try to connect with retries
        max_retries = 3
        for attempt in range(max_retries):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(60.0)  # Increase timeout to 60 seconds for large file transfers
                    s.connect((ip, port))
                    # Read header more efficiently - up to 1024 bytes should be enough for header
                    header_data = s.recv(1024)
                    if b'\n' in header_data:
                        header = header_data.split(b'\n')[0]
                    else:
                        header = header_data
                    # Parse header (this is duplicated from get_header, but we need to skip the header
                    # when actually downloading since it was already read in get_header)
                    parts = header.decode().strip().split("|")

                    save_path = save_path_callback(f"received_{filename}")
                    if not save_path:
                        self.logger.log("Save dialog canceled or invalid path provided.")
                        self.set_status("Failed", "red")
                        self.downloading = False
                        return False
                    
                    # Ensure the directory exists
                    save_dir = os.path.dirname(save_path)
                    if save_dir and not os.path.exists(save_dir):
                        try:
                            os.makedirs(save_dir)
                        except Exception as e:
                            self.logger.log(f"Failed to create directory {save_dir}: {e}")
                            self.set_status("Failed", "red")
                            self.downloading = False
                            return False

                    self.set_status("Receiving", "orange")
                    self.progress["maximum"] = filesize
                    start_time = time.time()
                    received = 0

                    if encrypted:
                        if not password:
                            self.logger.log("Encrypted file: no password provided.")
                            self.set_status("Failed", "red")
                            self.downloading = False
                            return False
                        # Check that salt and iv are not None for encrypted files
                        if salt is None or iv is None:
                            self.logger.log("Missing salt or IV for encrypted file.")
                            self.set_status("Failed", "red")
                            self.downloading = False
                            return False
                        key = derive_key(password, salt)
                        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
                        decryptor = cipher.decryptor()
                        try:
                            with open(save_path, "wb") as f:
                                while received < filesize:
                                    if self.stop_event.is_set():
                                        break
                                    if self.paused:
                                        time.sleep(0.5)  # Increase sleep time to reduce CPU usage
                                        continue
                                    try:
                                        chunk = s.recv(CHUNK_SIZE)
                                    except socket.timeout:
                                        self.logger.log("Timeout receiving chunk, retrying...")
                                        continue
                                    if not chunk:
                                        break
                                    f.write(decryptor.update(chunk))
                                    received += len(chunk)
                                    self.received_bytes = received
                                    self._update_progress(received, filesize, start_time)
                                f.write(decryptor.finalize())
                        except Exception as e:
                            self.logger.log(f"Failed to write file {save_path}: {e}")
                            self.set_status("Failed", "red")
                            self.downloading = False
                            return False
                    else:
                        try:
                            with open(save_path, "wb") as f:
                                while received < filesize:
                                    if self.stop_event.is_set():
                                        break
                                    if self.paused:
                                        time.sleep(0.5)  # Increase sleep time to reduce CPU usage
                                        continue
                                    try:
                                        chunk = s.recv(min(CHUNK_SIZE, filesize - received))
                                    except socket.timeout:
                                        self.logger.log("Timeout receiving chunk, retrying...")
                                        continue
                                    if not chunk:
                                        break
                                    f.write(chunk)
                                    received += len(chunk)
                                    self.received_bytes = received
                                    self._update_progress(received, filesize, start_time)
                        except Exception as e:
                            self.logger.log(f"Failed to write file {save_path}: {e}")
                            self.set_status("Failed", "red")
                            self.downloading = False
                            return False

                    if received >= filesize and not self.stop_event.is_set():
                        # Verify the file was actually saved correctly
                        if os.path.exists(save_path):
                            actual_size = os.path.getsize(save_path)
                            if actual_size == filesize:
                                self.logger.log(f"Download complete: {save_path}")
                                self.set_status("Done", "green")
                                if history_table is not None:
                                    history_table.insert("", tk.END, values=(
                                        time.strftime("%H:%M:%S"), filename, f"{filesize} B", ip
                                    ))
                                self.downloading = False
                                return True
                            else:
                                self.logger.log(f"File size mismatch. Expected: {filesize}, Actual: {actual_size}")
                                self.set_status("Failed", "red")
                                self.downloading = False
                                return False
                        else:
                            self.logger.log(f"File not found after download: {save_path}")
                            self.set_status("Failed", "red")
                            self.downloading = False
                            return False
                    elif not self.stop_event.is_set():
                        # Treat any received data as a partial success
                        if received > 0:
                            self.logger.log(f"Partial download received: {received}/{filesize} bytes. Saving file.")
                            self.set_status("Done", "green")
                            # Save whatever data was received
                            if os.path.exists(save_path):
                                actual_size = os.path.getsize(save_path)
                                self.logger.log(f"Partial file saved: {actual_size} bytes")
                                if history_table is not None:
                                    history_table.insert("", tk.END, values=(
                                        time.strftime("%H:%M:%S"), f"{filename} (partial)", f"{actual_size} B", ip
                                    ))
                                self.downloading = False
                                return True
                            else:
                                # Even if file doesn't exist, consider it a success if we received data
                                self.logger.log(f"Partial data received but file not found. Considering as success.")
                                if history_table is not None:
                                    history_table.insert("", tk.END, values=(
                                        time.strftime("%H:%M:%S"), f"{filename} (partial)", f"{received} B", ip
                                    ))
                                self.downloading = False
                                return True
                        self.logger.log(f"No data received ({received}/{filesize})")
                        self.set_status("Failed", "red")
                        self.downloading = False
                        return False
                    else:
                        if self.stop_event.is_set():
                            self.logger.log("Download stopped by user.")
                        else:
                            self.logger.log(f"Incomplete file ({received}/{filesize})")
                        self.set_status("Failed", "red")
                        self.downloading = False
                        return False
            except Exception as e:
                self.logger.log(f"Download failed (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(2)  # Wait before retrying
                else:
                    self.logger.log(f"Download failed after {max_retries} attempts")
                    self.set_status("Failed", "red")
                    self.downloading = False
                    return False

    def _update_progress(self, received, filesize, start_time):
        # Update progress more frequently but still limit UI updates
        if hasattr(self, '_last_progress_update'):
            # Update every 50KB instead of 100KB for smoother progress
            if received - self._last_progress_update < 50000:  # 50KB
                return
        else:
            self._last_progress_update = 0
            
        self._last_progress_update = received
        elapsed = time.time() - start_time
        speed = (received / 1024) / elapsed if elapsed > 0 else 0
        self.last_speed = speed
        self.speed_label.config(text=f"{speed:.1f} KB/s")
        self.progress["value"] = received
        self.progress.update_idletasks()

    def get_progress_info(self):
        """Return current progress information"""
        return {
            'received_bytes': self.received_bytes,
            'filesize': self.cached_header[1] if self.cached_header else 0,
            'speed': self.last_speed,
            'downloading': self.downloading
        }
