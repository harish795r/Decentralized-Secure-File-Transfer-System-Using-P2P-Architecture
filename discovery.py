import socket
import threading
import time

DISCOVERY_PORT = 60000
DISCOVERY_MSG = b"FILE_PEER_DISCOVER"
REQUEST_PORT = 60001

class PeerDiscovery:
    def __init__(self, logger, name="Peer"):
        self.logger = logger
        self.peers = {}
        self.running = False
        self.name = name
        self.lock = threading.Lock()
        self.actual_port = None
        self.listen_socket = None

    def start(self):
        self.running = True
        threading.Thread(target=self._broadcast_presence, daemon=True).start()
        threading.Thread(target=self._listen_for_peers, daemon=True).start()
        self.logger.log("Peer discovery started.")

    def stop(self):
        self.running = False
        # Close the listening socket to release the port immediately
        if self.listen_socket:
            try:
                self.listen_socket.close()
            except:
                pass
        self.logger.log("Peer discovery stopped.")

    def _broadcast_presence(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        msg = f"{DISCOVERY_MSG.decode()}|{self.name}".encode()
        # Use the actual port for broadcasting, or fall back to default
        port = self.actual_port if self.actual_port else DISCOVERY_PORT
        while self.running:
            try:
                s.sendto(msg, ('<broadcast>', port))
            except Exception as e:
                self.logger.log(f"Broadcast error: {e}")
            time.sleep(2)
        s.close()

    def _listen_for_peers(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Try to bind to the default port, if it's in use, try alternative ports
        port = DISCOVERY_PORT
        while True:
            try:
                s.bind(('', port))
                self.actual_port = port
                self.listen_socket = s
                self.logger.log(f"Peer discovery listening on port {port}")
                break
            except OSError as e:
                if e.errno == 48:  # Address already in use
                    self.logger.log(f"Port {port} in use, trying {port + 1}")
                    port += 1
                    if port > DISCOVERY_PORT + 100:  # Don't try too many ports
                        self.logger.log(f"Failed to find available port after trying {port - DISCOVERY_PORT} ports")
                        return
                else:
                    self.logger.log(f"Error binding to port {port}: {e}")
                    return
        
        s.settimeout(1)
        while self.running:
            try:
                msg, addr = s.recvfrom(1024)
                parts = msg.decode().split('|')
                if parts[0] == DISCOVERY_MSG.decode():
                    ip = addr[0]
                    name = parts[1] if len(parts) > 1 else ip
                    with self.lock:
                        if ip not in self.peers:
                            self.peers[ip] = name
                            self.logger.log(f"Discovered peer: {name} ({ip})")
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:  # Only log if we're still supposed to be running
                    self.logger.log(f"Error in peer discovery: {e}")
        s.close()

    def get_peers(self):
        with self.lock:
            return dict(self.peers)