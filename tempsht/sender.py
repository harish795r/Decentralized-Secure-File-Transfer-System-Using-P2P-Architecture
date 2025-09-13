import os
import socket
import threading

CHUNK_SIZE = 4096
TCP_PORT = 5000

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
