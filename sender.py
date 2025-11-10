import socket
import threading
import os
import base64
import time
from utils import derive_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

CHUNK_SIZE = 4096

class Sender:
    def __init__(self, logger, status_label):
        self.logger = logger
        self.status_label = status_label
        self.tcp_thread = None
        self.stop_event = threading.Event()
        self.filepath = None
        self.filesize = 0
        self.encrypt = False
        self.password = None
        self.paused = False
        self.sent_bytes = 0
        self.last_speed = 0
        self.start_time = 0

    def set_file(self, path):
        self.filepath = path
        self.filesize = os.path.getsize(path) if path else 0
        self.sent_bytes = 0
        self.logger.log(f"File set for sending: {path} ({self.filesize} bytes)")

    def start(self, bind_ip="0.0.0.0", tcp_port=5000, encrypt=False, password=None):
        if not self.filepath:
            self.logger.log("No file selected to send.")
            return False
        if encrypt and not password:
            self.logger.log("Encryption enabled but no password provided.")
            return False

        self.encrypt = encrypt
        self.password = password
        self.stop_event.clear()
        self.paused = False
        self.sent_bytes = 0
        self.start_time = time.time()
        
        # Try to start the server on the requested port, or find an alternative
        actual_port = self._start_server(bind_ip, tcp_port)
        if actual_port is None:
            self.logger.log("Failed to start sender server on any port.")
            return False
            
        self.logger.log(f"Sender TCP server started at {bind_ip}:{actual_port}")
        self.set_status("Sending", "blue")
        return True
        
    def _start_server(self, bind_ip, tcp_port):
        """Try to start the server on the requested port, or find an alternative"""
        port = tcp_port
        max_attempts = 100
        for attempt in range(max_attempts):
            serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                serv.bind((bind_ip, port))
                serv.listen(5)
                self.logger.log(f"Successfully bound to port {port}")
                # Start the server thread with the actual port we're using
                self.tcp_thread = threading.Thread(target=self._tcp_server_with_port,
                                                   args=(serv, port),
                                                   daemon=True)
                self.tcp_thread.start()
                return port
            except Exception as e:
                self.logger.log(f"Failed to bind to port {port}: {e}")
                serv.close()
                port += 1
                if attempt < max_attempts - 1:
                    time.sleep(0.1)  # Small delay before trying next port
                else:
                    self.logger.log(f"Failed to find available port after trying {max_attempts} ports")
                    return None
        return None
        
    def _tcp_server_with_port(self, serv, actual_port):
        """Server thread function that uses a pre-bound socket"""
        serv.settimeout(1.0)
        try:
            while not self.stop_event.is_set():
                try:
                    conn, addr = serv.accept()
                    conn.settimeout(5.0)
                except socket.timeout:
                    continue
                if conn:
                    self.logger.log(f"Client connected: {addr}")
                    try:
                        # Check that filepath is not None before proceeding
                        if self.filepath is None:
                            self.logger.log("No file selected to send.")
                            conn.close()
                            continue
                            
                        if self.encrypt:
                            salt = os.urandom(16)
                            iv = os.urandom(16)
                            # Check that password is not None before proceeding
                            if self.password is None:
                                self.logger.log("Encryption enabled but no password provided.")
                                conn.close()
                                continue
                            key = derive_key(self.password, salt)
                            salt_b64 = base64.b64encode(salt).decode()
                            iv_b64 = base64.b64encode(iv).decode()
                            header = f"{os.path.basename(self.filepath)}|{self.filesize}|{salt_b64}|{iv_b64}\n".encode()
                            conn.sendall(header)

                            cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
                            encryptor = cipher.encryptor()

                            with open(self.filepath, 'rb') as f:
                                self.sent_bytes = 0
                                while not self.stop_event.is_set():
                                    # Handle pause
                                    while self.paused and not self.stop_event.is_set():
                                        time.sleep(0.1)
                                    
                                    chunk = f.read(CHUNK_SIZE)
                                    if not chunk: break
                                    try:
                                        conn.sendall(encryptor.update(chunk))
                                        self.sent_bytes += len(chunk)
                                        # Update speed calculation
                                        elapsed = time.time() - self.start_time
                                        if elapsed > 0:
                                            self.last_speed = (self.sent_bytes / 1024) / elapsed
                                    except socket.timeout:
                                        self.logger.log("Timeout sending chunk.")
                                        break
                                    # Add a small delay to prevent excessive CPU usage
                                    time.sleep(0.001)
                            conn.sendall(encryptor.finalize())
                        else:
                            header = f"{os.path.basename(self.filepath)}|{self.filesize}\n".encode()
                            conn.sendall(header)
                            with open(self.filepath, 'rb') as f:
                                self.sent_bytes = 0
                                while not self.stop_event.is_set():
                                    # Handle pause
                                    while self.paused and not self.stop_event.is_set():
                                        time.sleep(0.1)
                                    
                                    chunk = f.read(CHUNK_SIZE)
                                    if not chunk: break
                                    try:
                                        conn.sendall(chunk)
                                        self.sent_bytes += len(chunk)
                                        # Update speed calculation
                                        elapsed = time.time() - self.start_time
                                        if elapsed > 0:
                                            self.last_speed = (self.sent_bytes / 1024) / elapsed
                                    except socket.timeout:
                                        self.logger.log("Timeout sending chunk.")
                                        break
                                    # Add a small delay to prevent excessive CPU usage
                                    time.sleep(0.001)
                        self.set_status("Done", "green")
                    except Exception as e:
                        self.logger.log(f"Error during file send: {e}")
                        self.set_status("Failed", "red")
                    finally:
                        conn.close()
        finally:
            serv.close()
            self.logger.log("TCP server stopped.")

    def stop(self):
        self.stop_event.set()
        self.set_status("Idle", "green")
        self.logger.log("Sender stopping...")

    def set_status(self, text, color):
        self.status_label.config(text=text, fg=color)

