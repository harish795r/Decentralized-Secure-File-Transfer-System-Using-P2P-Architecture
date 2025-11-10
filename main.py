from startup_auth import verify_license
verify_license()


import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
import threading
import argparse
import sys
import socket
import time
from utils import local_ip
from logger import Logger
from sender import Sender
from receiver import Receiver
from discovery import PeerDiscovery
import os

REQUEST_PORT = 60001


class App:
    def __init__(self, root, mode, tcp_port):
        self.root = root
        self.mode = mode
        self.tcp_port = tcp_port
        self.root.title(f"P2P File Transfer ({mode.upper()} mode, port {tcp_port})")
        self.root.geometry("1000x650")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.logger = None
        self.discovery = None
        self.sender = None
        self.receiver = None
        self.selected_file_path = None

        self.container = tk.Frame(root)
        self.container.pack(fill="both", expand=True)

        self.frames = {}
        for F in (ModeScreen, SendScreen, ReceiveScreen):
            frame = F(self.container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        # start directly in given mode
        if mode == "send":
            self.show_frame(SendScreen)
        elif mode == "receive":
            self.show_frame(ReceiveScreen)
        else:
            self.show_frame(ModeScreen)

    def show_frame(self, frame_class):
        frame = self.frames[frame_class]
        frame.tkraise()

    def on_close(self):
        if self.discovery:
            self.discovery.stop()
        if self.sender:
            self.sender.stop()
        if self.receiver:
            self.receiver.stop_download()
        self.root.destroy()


class ModeScreen(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        tk.Label(self, text="Select Mode", font=("Segoe UI", 16, "bold")).pack(pady=30)
        tk.Button(self, text="Send Files", font=("Segoe UI", 14), width=20,
                  command=lambda: controller.show_frame(SendScreen)).pack(pady=10)
        tk.Button(self, text="Receive Files", font=("Segoe UI", 14), width=20,
                  command=lambda: controller.show_frame(ReceiveScreen)).pack(pady=10)


class SendScreen(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        tk.Label(self, text=f"Send Files (Port {controller.tcp_port})",
                 font=("Segoe UI", 16, "bold")).pack(pady=10)

        top = tk.Frame(self)
        top.pack(pady=10)
        self.file_label = tk.Label(top, text="No file selected")
        self.file_label.pack(side=tk.LEFT, padx=10)
        tk.Button(top, text="Select File", command=self.select_file).pack(side=tk.LEFT)

        self.peers_box = tk.Listbox(self, height=8, width=50)
        self.peers_box.pack(pady=10)
        tk.Button(self, text="Scan for Peers", command=self.scan_peers).pack(pady=5)
        tk.Button(self, text="Send to Selected Peer", command=self.send_request).pack(pady=5)
        tk.Button(self, text="Back", command=lambda: controller.show_frame(ModeScreen)).pack(pady=10)

        # Progress section for sending
        progress_frame = tk.LabelFrame(self, text="Transfer Progress")
        progress_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.progress = ttk.Progressbar(progress_frame, mode='determinate')
        self.progress.pack(fill=tk.X, padx=5, pady=5)
        
        self.speed_label = tk.Label(progress_frame, text="Speed: 0 KB/s")
        self.speed_label.pack(pady=2)
        
        # Control buttons for sending
        control_frame = tk.Frame(progress_frame)
        control_frame.pack(pady=5)
        
        self.pause_button = tk.Button(control_frame, text="Pause", command=self.toggle_pause, state=tk.DISABLED)
        self.pause_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = tk.Button(control_frame, text="Stop Sending", command=self.stop_sending, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        log_frame = tk.LabelFrame(self, text="Logs")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        log_text = tk.Text(log_frame, height=8, wrap=tk.NONE)
        log_text.pack(fill=tk.BOTH, expand=True)
        
        # Initialize logger and discovery only if not already done
        if not controller.logger:
            controller.logger = Logger(log_text)
        if not controller.discovery:
            controller.discovery = PeerDiscovery(controller.logger, name=socket.gethostname())
            controller.discovery.start()

        self.sender = Sender(controller.logger, tk.Label(self))
        controller.sender = self.sender
        
        # Start progress updater thread
        self.progress_updater_running = True
        threading.Thread(target=self._update_progress, daemon=True).start()

    def select_file(self):
        path = filedialog.askopenfilename()
        if not path:
            return
        self.file_label.config(text=os.path.basename(path))
        self.controller.selected_file_path = path
        self.sender.set_file(path)

    def scan_peers(self):
        self.peers_box.delete(0, tk.END)
        if self.controller.discovery:
            peers = self.controller.discovery.get_peers()
            for ip, name in peers.items():
                self.peers_box.insert(tk.END, f"{name} ({ip})")

        # always add localhost for single-PC test
        if "127.0.0.1" not in [p.split("(")[-1].strip(")") for p in self.peers_box.get(0, tk.END)]:
            self.peers_box.insert(tk.END, f"Localhost (127.0.0.1)")

    def send_request(self):
        if not self.controller.selected_file_path:
            messagebox.showwarning("No File", "Select a file first.")
            return
        sel = self.peers_box.curselection()
        if not sel:
            messagebox.showwarning("No Peer", "Select a peer to send to.")
            return
        peer_line = self.peers_box.get(sel[0])
        ip = peer_line.split("(")[-1].strip(")")
        filename = os.path.basename(self.controller.selected_file_path)
        filesize = os.path.getsize(self.controller.selected_file_path)

        if self.controller.logger:
            self.controller.logger.log(f"Attempting to send request to {ip}:{REQUEST_PORT}")

        # Try to connect with retries
        max_retries = 3
        for attempt in range(max_retries):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10)  # Increase timeout to 10 seconds
                s.connect((ip, REQUEST_PORT))
                if self.controller.logger:
                    self.controller.logger.log(f"Connected to {ip}:{REQUEST_PORT}")
                s.sendall(f"REQUEST:{filename}:{filesize}:{self.controller.tcp_port}".encode())
                if self.controller.logger:
                    self.controller.logger.log(f"Sent request data")
                resp = s.recv(64).decode()
                if self.controller.logger:
                    self.controller.logger.log(f"Received response: {resp}")
                s.close()
                if resp == "ACCEPT":
                    messagebox.showinfo("Accepted", f"{ip} accepted the transfer.")
                    # Enable control buttons
                    self.pause_button.config(state=tk.NORMAL, text="Pause")
                    self.stop_button.config(state=tk.NORMAL)
                    # Reset progress bar
                    self.progress["value"] = 0
                    self.progress["maximum"] = filesize
                    self.speed_label.config(text="Speed: 0 KB/s")
                    # Use the new start method that handles port conflicts
                    threading.Thread(target=lambda: self.sender.start("0.0.0.0", self.controller.tcp_port, 
                                                                     self.sender.encrypt, self.sender.password),
                                     daemon=True).start()
                    return  # Success, exit the retry loop
                else:
                    messagebox.showwarning("Declined", f"{ip} declined the transfer.")
                    return  # No point in retrying if declined
            except Exception as e:
                if self.controller.logger:
                    self.controller.logger.log(f"Failed to send request to {ip}:{REQUEST_PORT} (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(1)  # Wait before retrying
                else:
                    messagebox.showerror("Connection Failed", f"Could not connect to {ip}:{REQUEST_PORT} after {max_retries} attempts\nError: {e}")

    def toggle_pause(self):
        if self.sender:
            # Toggle pause state
            if self.sender.paused:
                self.sender.paused = False
                self.pause_button.config(text="Pause")
                if self.controller.logger:
                    self.controller.logger.log("Sending resumed.")
            else:
                self.sender.paused = True
                self.pause_button.config(text="Resume")
                if self.controller.logger:
                    self.controller.logger.log("Sending paused.")

    def stop_sending(self):
        if self.sender:
            self.sender.stop()
            self.pause_button.config(state=tk.DISABLED, text="Pause")
            self.stop_button.config(state=tk.DISABLED)
            if self.controller.logger:
                self.controller.logger.log("Sending stopped.")

    def _update_progress(self):
        """Update progress bar with current send progress"""
        while self.progress_updater_running:
            try:
                # Update progress if sender has progress info
                if self.sender and hasattr(self.sender, 'sent_bytes') and hasattr(self.sender, 'filesize'):
                    sent = getattr(self.sender, 'sent_bytes', 0)
                    total = getattr(self.sender, 'filesize', 1)
                    self.progress["value"] = sent
                    # Update speed if available
                    if hasattr(self.sender, 'last_speed'):
                        speed = getattr(self.sender, 'last_speed', 0)
                        self.speed_label.config(text=f"Speed: {speed:.1f} KB/s")
                time.sleep(0.1)  # Update 10 times per second for smoother progress
            except Exception as e:
                if self.controller.logger:
                    self.controller.logger.log(f"Progress update error: {e}")
                time.sleep(1)
                
    def destroy(self):
        """Clean up when the frame is destroyed"""
        self.progress_updater_running = False
        super().destroy()


class ReceiveScreen(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        tk.Label(self, text=f"Receive Files (Port {controller.tcp_port})",
                 font=("Segoe UI", 16, "bold")).pack(pady=10)

        self.status_label = tk.Label(self, text="Listening for requests...", fg="green")
        self.status_label.pack(pady=10)
        tk.Button(self, text="Back", command=lambda: controller.show_frame(ModeScreen)).pack(pady=10)

        # Progress section for receiving
        progress_frame = tk.LabelFrame(self, text="Transfer Progress")
        progress_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.progress = ttk.Progressbar(progress_frame, mode='determinate')
        self.progress.pack(fill=tk.X, padx=5, pady=5)
        
        self.speed_label = tk.Label(progress_frame, text="Speed: 0 KB/s")
        self.speed_label.pack(pady=2)
        
        # Control buttons for receiving
        control_frame = tk.Frame(progress_frame)
        control_frame.pack(pady=5)
        
        self.pause_button = tk.Button(control_frame, text="Pause", command=self.toggle_pause, state=tk.DISABLED)
        self.pause_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = tk.Button(control_frame, text="Stop Receiving", command=self.stop_receiving, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        log_frame = tk.LabelFrame(self, text="Logs")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        log_text = tk.Text(log_frame, height=8, wrap=tk.NONE)
        log_text.pack(fill=tk.BOTH, expand=True)
        
        # Initialize logger and discovery only if not already done
        if not controller.logger:
            controller.logger = Logger(log_text)
        if not controller.discovery:
            controller.discovery = PeerDiscovery(controller.logger, name=socket.gethostname())
            controller.discovery.start()
            
        # Initialize receiver with our progress bar and speed label
        controller.receiver = Receiver(controller.logger, self.status_label,
                                       self.progress, self.speed_label)
        self.receiver = controller.receiver

        threading.Thread(target=self.listen_for_requests, daemon=True).start()
        
        # Start progress updater thread
        self.progress_updater_running = True
        threading.Thread(target=self._update_progress, daemon=True).start()

    def listen_for_requests(self):
        while True:  # Keep trying to listen even if there are errors
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Also set SO_REUSEPORT if available (Unix systems)
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except AttributeError:
                pass  # SO_REUSEPORT not available on this platform
            try:
                s.bind(("", REQUEST_PORT))
                s.listen(5)
                s.settimeout(5.0)  # Set timeout for accept() calls
                if self.controller.logger:
                    self.controller.logger.log(f"Listening for incoming requests on port {REQUEST_PORT}")
                while True:
                    conn = None
                    try:
                        conn, addr = s.accept()
                        conn.settimeout(10.0)  # Set timeout for connection operations
                        if self.controller.logger:
                            self.controller.logger.log(f"Connection received from {addr[0]}")
                        data = conn.recv(1024).decode().split(":")
                        if self.controller.logger:
                            self.controller.logger.log(f"Received data: {data}")
                        if len(data) >= 4 and data[0] == "REQUEST":
                            filename, filesize, sender_port = data[1], data[2], int(data[3])
                            res = messagebox.askyesno(
                                "Incoming File",
                                f"{addr[0]} wants to send '{filename}' ({filesize} bytes). Accept?"
                            )
                            if res:
                                conn.sendall(b"ACCEPT")
                                # Enable control buttons for receiving
                                self.pause_button.config(state=tk.NORMAL, text="Pause")
                                self.stop_button.config(state=tk.NORMAL)
                                # Reset progress bar
                                self.progress["value"] = 0
                                self.progress["maximum"] = int(filesize)
                                self.speed_label.config(text="Speed: 0 KB/s")
                                # Create a proper function to avoid lambda capture issues
                                def start_download_thread(ip, port):
                                    self._start_download(ip, port)
                                threading.Thread(
                                    target=start_download_thread,
                                    args=(addr[0], sender_port),
                                    daemon=True
                                ).start()
                            else:
                                conn.sendall(b"DECLINE")
                        if conn:
                            conn.close()
                    except socket.timeout:
                        # This is expected due to the timeout setting
                        continue
                    except Exception as e:
                        if self.controller.logger:
                            self.controller.logger.log(f"Error handling connection: {e}")
                        if conn:
                            try:
                                conn.close()
                            except:
                                pass
            except Exception as e:
                if self.controller.logger:
                    self.controller.logger.log(f"Error in request listener: {e}")
                # Wait a bit before trying to restart the listener
                time.sleep(2)
            finally:
                try:
                    s.close()
                except:
                    pass

    def _start_download(self, ip, sender_port):
        if self.controller.logger:
            self.controller.logger.log(f"Starting download from {ip}:{sender_port}")
        self.controller.receiver.get_header(ip, sender_port)
        def ask_save(default_name):
            return filedialog.asksaveasfilename(initialfile=default_name)
        self.controller.receiver.download(ip, sender_port, ask_save, ttk.Treeview(self))
        # Disable control buttons when download is complete
        self.pause_button.config(state=tk.DISABLED, text="Pause")
        self.stop_button.config(state=tk.DISABLED)

    def toggle_pause(self):
        if self.receiver:
            self.receiver.toggle_pause()
            # Update button text based on pause state
            if self.receiver.paused:
                self.pause_button.config(text="Resume")
                if self.controller.logger:
                    self.controller.logger.log("Download resumed.")
            else:
                self.pause_button.config(text="Pause")
                if self.controller.logger:
                    self.controller.logger.log("Download paused.")

    def stop_receiving(self):
        if self.receiver:
            self.receiver.stop_download()
            self.pause_button.config(state=tk.DISABLED, text="Pause")
            self.stop_button.config(state=tk.DISABLED)
            if self.controller.logger:
                self.controller.logger.log("Download stopped.")

    def _update_progress(self):
        """Update progress bar with current receive progress"""
        while self.progress_updater_running:
            try:
                # Update progress if receiver has progress info
                if self.receiver and hasattr(self.receiver, 'received_bytes') and hasattr(self.receiver, 'cached_header'):
                    received = getattr(self.receiver, 'received_bytes', 0)
                    cached_header = getattr(self.receiver, 'cached_header', None)
                    if cached_header:
                        total = cached_header[1]  # filesize is the second element
                        self.progress["value"] = received
                        # Update speed if available
                        if hasattr(self.receiver, 'last_speed'):
                            speed = getattr(self.receiver, 'last_speed', 0)
                            self.speed_label.config(text=f"Speed: {speed:.1f} KB/s")
                time.sleep(0.1)  # Update 10 times per second for smoother progress
            except Exception as e:
                if self.controller.logger:
                    self.controller.logger.log(f"Progress update error: {e}")
                time.sleep(1)
                
    def destroy(self):
        """Clean up when the frame is destroyed"""
        self.progress_updater_running = False
        super().destroy()


def parse_args():
    parser = argparse.ArgumentParser(description="Local P2P File Transfer")
    parser.add_argument("--mode", choices=["send", "receive", "both"], default="both",
                        help="Run in send, receive, or both modes")
    parser.add_argument("--port", type=int, default=5000, help="TCP port for file transfer")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    root = tk.Tk()
    app = App(root, args.mode, args.port)
    root.mainloop()