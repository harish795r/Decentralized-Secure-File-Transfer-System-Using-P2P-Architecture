from startup_auth import verify_license
verify_license()


import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
import threading
import argparse
import sys
import socket
import time
import os
from utils import local_ip
from logger import Logger
from sender import Sender
from receiver import Receiver
from discovery import PeerDiscovery

# Styling constants
BG_COLOR = "#121212"          # Deep dark background
FG_COLOR = "#FFFFFF"          # Bright white text
ACCENT_COLOR = "#00FFFF"      # Neon blue accent
HIGHLIGHT_COLOR = "#00BFFF"   # Bright blue highlight
SUCCESS_COLOR = "#00FA9A"     # Medium spring green success
WARNING_COLOR = "#FFD700"     # Gold warning
DARK_BG = "#1E1E1E"          # Slightly lighter dark
FRAME_BG = "#2D2D2D"         # Frame background
FONT_FAMILY = ("Segoe UI", 10)
TITLE_FONT = ("Segoe UI", 18, "bold")
HEADER_FONT = ("Segoe UI", 12, "bold")

REQUEST_PORT = 60001


class App:
    def __init__(self, root, mode, tcp_port):
        self.root = root
        self.mode = mode
        self.tcp_port = tcp_port
        self.root.title(f"P2P File Transfer ({mode.upper()} mode, port {tcp_port})")
        # Make window 20% bigger (1000x650 -> 1200x780)
        self.root.geometry("1200x780")
        self.root.minsize(960, 600)  # 20% bigger minimum size too
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Apply styling
        self.root.configure(bg=BG_COLOR)
        
        # Configure styles
        self._configure_styles()

        self.logger = None
        self.discovery = None
        self.sender = None
        self.receiver = None
        self.selected_file_path = None

        self.container = tk.Frame(root, bg=BG_COLOR)
        self.container.pack(fill="both", expand=True, padx=10, pady=10)
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for F in (ModeScreen, SendScreen, ReceiveScreen):
            frame = F(self.container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")
            # Configure grid weights for responsive design
            frame.grid_rowconfigure(0, weight=1)
            frame.grid_columnconfigure(0, weight=1)

        # start directly in given mode
        if mode == "send":
            self.show_frame(SendScreen)
        elif mode == "receive":
            self.show_frame(ReceiveScreen)
        else:
            self.show_frame(ModeScreen)
    
    def _configure_styles(self):
        # Configure ttk styles
        style = ttk.Style()
        style.theme_use('default')
        
        # Progress bar styling for dark theme
        style.configure("Horizontal.TProgressbar", 
                       troughcolor="#383838",
                       background=ACCENT_COLOR,
                       thickness=20,
                       troughrelief=tk.FLAT)
        style.configure("Horizontal.TProgressbar", relief=tk.FLAT)
        
        # Button styling is handled manually since we're using regular tk.Buttons
        # for more control over appearance
    
    def show_frame(self, frame_class):
        frame = self.frames[frame_class]
        frame.tkraise()
        # Make sure the frame expands properly
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

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
        super().__init__(parent, bg=BG_COLOR)
        self.controller = controller
        
        # Configure grid for responsive design
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        # Create a gradient-like effect with frames
        top_frame = tk.Frame(self, bg="#1a1a1a")
        top_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        top_frame.grid_rowconfigure(1, weight=1)
        top_frame.grid_columnconfigure(0, weight=1)
        
        # Header
        header_frame = tk.Frame(top_frame, bg="#1a1a1a")
        header_frame.grid(row=0, column=0, pady=30)
        header_frame.grid_columnconfigure(0, weight=1)
        
        title_label = tk.Label(header_frame, text="P2P File Transfer", font=TITLE_FONT, 
                              fg=ACCENT_COLOR, bg="#1a1a1a")
        title_label.grid(row=0, column=0, sticky="ew")
        
        subtitle_label = tk.Label(header_frame, text="Secure peer-to-peer file sharing", 
                                 font=FONT_FAMILY, fg="#CCCCCC", bg="#1a1a1a")
        subtitle_label.grid(row=1, column=0, pady=(10, 0), sticky="ew")
        
        # Mode selection
        mode_frame = tk.Frame(top_frame, bg="#1a1a1a")
        mode_frame.grid(row=1, column=0, pady=50)
        mode_frame.grid_rowconfigure(0, weight=1)
        mode_frame.grid_rowconfigure(1, weight=1)
        mode_frame.grid_columnconfigure(0, weight=1)
        mode_frame.grid_columnconfigure(1, weight=1)
        
        # Modern card-style buttons
        send_frame = tk.Frame(mode_frame, bg=FRAME_BG, relief=tk.FLAT, bd=0)
        send_frame.grid(row=0, column=0, padx=20, pady=10, sticky="nsew")
        send_frame.grid_rowconfigure(1, weight=1)
        send_frame.grid_columnconfigure(0, weight=1)
        
        send_button = tk.Button(send_frame, text="Send Files", font=HEADER_FONT, 
                               width=25, height=3, bg="#FFFFFF", fg="#000000",
                               activebackground=ACCENT_COLOR, activeforeground="#000000",
                               relief=tk.FLAT, bd=0, highlightthickness=0,
                               command=lambda: controller.show_frame(SendScreen))
        send_button.grid(row=0, column=0, pady=2, padx=2, sticky="ew")
        
        send_desc = tk.Label(send_frame, text="Share files with peers on your network", 
                            font=("Segoe UI", 9), fg="#AAAAAA", bg=FRAME_BG)
        send_desc.grid(row=1, column=0, pady=(0, 10), sticky="s")
        
        receive_frame = tk.Frame(mode_frame, bg=FRAME_BG, relief=tk.FLAT, bd=0)
        receive_frame.grid(row=0, column=1, padx=20, pady=10, sticky="nsew")
        receive_frame.grid_rowconfigure(1, weight=1)
        receive_frame.grid_columnconfigure(0, weight=1)
        
        receive_button = tk.Button(receive_frame, text="Receive Files", font=HEADER_FONT, 
                                  width=25, height=3, bg="#FFFFFF", fg="#000000",
                                  activebackground=SUCCESS_COLOR, activeforeground="#000000",
                                  relief=tk.FLAT, bd=0, highlightthickness=0,
                                  command=lambda: controller.show_frame(ReceiveScreen))
        receive_button.grid(row=0, column=0, pady=2, padx=2, sticky="ew")
        
        receive_desc = tk.Label(receive_frame, text="Accept incoming file transfers", 
                               font=("Segoe UI", 9), fg="#AAAAAA", bg=FRAME_BG)
        receive_desc.grid(row=1, column=0, pady=(0, 10), sticky="s")


class SendScreen(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=BG_COLOR)
        self.controller = controller
        
        # Header with modern styling
        header_frame = tk.Frame(self, bg=DARK_BG)
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        title_label = tk.Label(header_frame, text=f"Send Files (Port {controller.tcp_port})",
                              font=TITLE_FONT, fg=ACCENT_COLOR, bg=DARK_BG)
        title_label.pack(side=tk.LEFT, padx=20, pady=15)
        
        back_button = tk.Button(header_frame, text="← Back", font=FONT_FAMILY,
                               bg="#FFFFFF", fg="#000000",
                               activebackground=WARNING_COLOR, activeforeground="#000000",
                               relief=tk.FLAT, bd=0,
                               command=lambda: controller.show_frame(ModeScreen))
        back_button.pack(side=tk.RIGHT, padx=20, pady=15)

        # Create main content area with activity log taking more space
        main_frame = tk.Frame(self, bg=BG_COLOR)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        main_frame.grid_rowconfigure(0, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)  # Left column
        main_frame.grid_columnconfigure(1, weight=3)  # Right column (activity log) gets more space
        
        # Left side - file selection, peers, and progress (smaller)
        left_frame = tk.Frame(main_frame, bg=BG_COLOR)
        left_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        left_frame.grid_columnconfigure(0, weight=1)
        
        # Right side - activity log (larger)
        right_frame = tk.Frame(main_frame, bg=BG_COLOR)
        right_frame.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        right_frame.grid_columnconfigure(0, weight=1)
        right_frame.grid_rowconfigure(0, weight=1)

        # File selection with modern card design
        file_frame = tk.Frame(left_frame, bg=FRAME_BG, relief=tk.FLAT, bd=0)
        file_frame.grid(row=0, column=0, sticky="ew", pady=(0, 15))
        file_frame.grid_columnconfigure(0, weight=1)
        
        file_header = tk.Label(file_frame, text="SELECT FILE", font=HEADER_FONT,
                              fg=FG_COLOR, bg=FRAME_BG)
        file_header.grid(row=0, column=0, sticky="w", padx=15, pady=(15, 5))
        
        file_inner_frame = tk.Frame(file_frame, bg=FRAME_BG)
        file_inner_frame.grid(row=1, column=0, sticky="ew", padx=15, pady=(0, 15))
        file_inner_frame.grid_columnconfigure(0, weight=1)
        
        self.file_label = tk.Label(file_inner_frame, text="No file selected", 
                                  font=FONT_FAMILY, fg="#AAAAAA", bg=FRAME_BG,
                                  anchor="w")
        self.file_label.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        
        select_button = tk.Button(file_inner_frame, text="Browse", font=FONT_FAMILY,
                                 bg="#FFFFFF", fg="#000000",
                                 activebackground=ACCENT_COLOR, activeforeground="#000000",
                                 relief=tk.FLAT, bd=0,
                                 command=self.select_file)
        select_button.grid(row=0, column=1)

        # Peers section with modern styling
        peers_frame = tk.Frame(left_frame, bg=FRAME_BG, relief=tk.FLAT, bd=0)
        peers_frame.grid(row=1, column=0, sticky="nsew", pady=(0, 15))
        peers_frame.grid_columnconfigure(0, weight=1)
        peers_frame.grid_rowconfigure(1, weight=1)
        
        peers_header = tk.Label(peers_frame, text="AVAILABLE PEERS", font=HEADER_FONT,
                               fg=FG_COLOR, bg=FRAME_BG)
        peers_header.grid(row=0, column=0, sticky="w", padx=15, pady=(15, 5))
        
        peers_inner_frame = tk.Frame(peers_frame, bg=FRAME_BG)
        peers_inner_frame.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))
        peers_inner_frame.grid_columnconfigure(0, weight=1)
        peers_inner_frame.grid_rowconfigure(0, weight=1)
        
        self.peers_box = tk.Listbox(peers_inner_frame, font=FONT_FAMILY,
                                   bg="#383838", fg=FG_COLOR, 
                                   selectbackground="#FFFFFF",  # White background when selected
                                   selectforeground="#000000",  # Black text when selected
                                   relief=tk.FLAT, bd=0,
                                   highlightthickness=0,
                                   activestyle="none")
        self.peers_box.grid(row=0, column=0, sticky="nsew")
        
        scrollbar = tk.Scrollbar(peers_inner_frame, orient=tk.VERTICAL, command=self.peers_box.yview,
                                bg=FRAME_BG, troughcolor=DARK_BG, activebackground=ACCENT_COLOR)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.peers_box.config(yscrollcommand=scrollbar.set)
        
        # Peer controls with modern styling
        peer_buttons_frame = tk.Frame(peers_frame, bg=FRAME_BG)
        peer_buttons_frame.grid(row=2, column=0, sticky="ew", padx=15, pady=(0, 15))
        peer_buttons_frame.grid_columnconfigure(0, weight=1)
        peer_buttons_frame.grid_columnconfigure(1, weight=1)
        
        scan_button = tk.Button(peer_buttons_frame, text="Scan Network", font=FONT_FAMILY,
                               bg="#FFFFFF", fg="#000000",
                               activebackground=ACCENT_COLOR, activeforeground="#000000",
                               relief=tk.FLAT, bd=0,
                               command=self.scan_peers)
        scan_button.grid(row=0, column=0, padx=(0, 10), sticky="ew")
        
        send_button = tk.Button(peer_buttons_frame, text="Send File", font=FONT_FAMILY,
                               bg="#FFFFFF", fg="#000000",
                               activebackground=SUCCESS_COLOR, activeforeground="#000000",
                               relief=tk.FLAT, bd=0,
                               command=self.send_request)
        send_button.grid(row=0, column=1, sticky="ew")

        # Progress section with modern styling
        progress_frame = tk.Frame(left_frame, bg=FRAME_BG, relief=tk.FLAT, bd=0)
        progress_frame.grid(row=2, column=0, sticky="ew")
        progress_frame.grid_columnconfigure(0, weight=1)
        
        progress_header = tk.Label(progress_frame, text="TRANSFER PROGRESS", font=HEADER_FONT,
                                  fg=FG_COLOR, bg=FRAME_BG)
        progress_header.grid(row=0, column=0, sticky="w", padx=15, pady=(15, 5))
        
        progress_inner_frame = tk.Frame(progress_frame, bg=FRAME_BG)
        progress_inner_frame.grid(row=1, column=0, sticky="ew", padx=15, pady=(0, 15))
        progress_inner_frame.grid_columnconfigure(0, weight=1)
        
        self.progress = ttk.Progressbar(progress_inner_frame, mode='determinate',
                                       style="Horizontal.TProgressbar")
        self.progress.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        self.speed_label = tk.Label(progress_inner_frame, text="Ready to transfer", 
                                   font=FONT_FAMILY, fg="#AAAAAA", bg=FRAME_BG)
        self.speed_label.grid(row=1, column=0, pady=(0, 15))
        
        # Control buttons with modern styling
        control_frame = tk.Frame(progress_inner_frame, bg=FRAME_BG)
        control_frame.grid(row=2, column=0, sticky="ew")
        control_frame.grid_columnconfigure(0, weight=1)
        control_frame.grid_columnconfigure(1, weight=1)
        
        self.pause_button = tk.Button(control_frame, text="Pause", font=FONT_FAMILY,
                                     bg="#FFFFFF", fg="#000000",
                                     activebackground=WARNING_COLOR, activeforeground="#000000",
                                     relief=tk.FLAT, bd=0,
                                     command=self.toggle_pause, state=tk.DISABLED)
        self.pause_button.grid(row=0, column=0, padx=(0, 10), sticky="ew")
        
        self.stop_button = tk.Button(control_frame, text="Stop", font=FONT_FAMILY,
                                    bg="#FFFFFF", fg="#000000",
                                    activebackground=HIGHLIGHT_COLOR, activeforeground="#000000",
                                    relief=tk.FLAT, bd=0,
                                    command=self.stop_sending, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, sticky="ew")

        # Logs section with modern styling on the right side (takes more space)
        log_frame = tk.Frame(right_frame, bg=FRAME_BG, relief=tk.FLAT, bd=0)
        log_frame.grid(row=0, column=0, sticky="nsew")
        log_frame.grid_columnconfigure(0, weight=1)
        log_frame.grid_rowconfigure(1, weight=1)
        
        log_header = tk.Label(log_frame, text="ACTIVITY LOG", font=HEADER_FONT,
                             fg=FG_COLOR, bg=FRAME_BG)
        log_header.grid(row=0, column=0, sticky="w", padx=15, pady=(15, 5))
        
        log_inner_frame = tk.Frame(log_frame, bg=FRAME_BG)
        log_inner_frame.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))
        log_inner_frame.grid_columnconfigure(0, weight=1)
        log_inner_frame.grid_rowconfigure(0, weight=1)
        
        log_text = tk.Text(log_inner_frame, font=FONT_FAMILY,
                          bg="#383838", fg=FG_COLOR, 
                          relief=tk.FLAT, bd=0,
                          wrap=tk.WORD,
                          padx=10, pady=10)
        log_text.grid(row=0, column=0, sticky="nsew")
        
        log_scrollbar = tk.Scrollbar(log_inner_frame, orient=tk.VERTICAL, command=log_text.yview,
                                    bg=FRAME_BG, troughcolor=DARK_BG, activebackground=ACCENT_COLOR)
        log_scrollbar.grid(row=0, column=1, sticky="ns")
        log_text.config(yscrollcommand=log_scrollbar.set)
        
        # Initialize logger and discovery only if not already done
        # Create separate logger for sender
        self.sender_logger = Logger(log_text)
        controller.logger = self.sender_logger
        
        if not controller.discovery:
            controller.discovery = PeerDiscovery(self.sender_logger, name=socket.gethostname())
            controller.discovery.start()

        self.sender = Sender(self.sender_logger, tk.Label(self))
        controller.sender = self.sender
        
        # Start progress updater thread
        self.progress_updater_running = True
        threading.Thread(target=self._update_progress, daemon=True).start()

    def select_file(self):
        path = filedialog.askopenfilename(
            title="Select file to send",
            filetypes=[
                ("All files", "*.*"),
                ("Documents", "*.pdf;*.doc;*.docx;*.txt"),
                ("Images", "*.jpg;*.jpeg;*.png;*.gif"),
                ("Videos", "*.mp4;*.avi;*.mkv"),
                ("Audio", "*.mp3;*.wav;*.flac")
            ]
        )
        if not path:
            return
        filename = os.path.basename(path)
        filesize = os.path.getsize(path)
        # Format file size in human readable format
        if filesize < 1024:
            size_str = f"{filesize} B"
        elif filesize < 1024 * 1024:
            size_str = f"{filesize // 1024} KB"
        elif filesize < 1024 * 1024 * 1024:
            size_str = f"{filesize // (1024 * 1024)} MB"
        else:
            size_str = f"{filesize // (1024 * 1024 * 1024)} GB"
        
        self.file_label.config(text=f"{filename} ({size_str})")
        self.controller.selected_file_path = path
        self.sender.set_file(path)

    def scan_peers(self):
        self.peers_box.delete(0, tk.END)
        if self.controller.discovery:
            peers = self.controller.discovery.get_peers()
            for ip, name in peers.items():
                # Highlight localhost differently
                if ip == "127.0.0.1":
                    display_text = f"{name} ({ip}) [Local]"
                else:
                    display_text = f"{name} ({ip})"
                self.peers_box.insert(tk.END, display_text)

        # always add localhost for single-PC test if not already present
        localhost_entry = "Localhost (127.0.0.1) [Local]"
        existing_peers = self.peers_box.get(0, tk.END)
        if not any("127.0.0.1" in peer for peer in existing_peers):
            self.peers_box.insert(tk.END, localhost_entry)

    def send_request(self):
        if not self.controller.selected_file_path:
            messagebox.showwarning("No File", "Select a file first.")
            return
        sel = self.peers_box.curselection()
        if not sel:
            messagebox.showwarning("No Peer", "Select a peer to send to.")
            return
        peer_line = self.peers_box.get(sel[0])
        # Extract IP address (handle both regular and localhost entries)
        ip_part = peer_line.split("(")[-1]
        ip = ip_part.split(")")[0]
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
        super().__init__(parent, bg=BG_COLOR)
        self.controller = controller
        
        # Header with modern styling
        header_frame = tk.Frame(self, bg=DARK_BG)
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        title_label = tk.Label(header_frame, text=f"Receive Files (Port {controller.tcp_port})",
                              font=TITLE_FONT, fg=ACCENT_COLOR, bg=DARK_BG)
        title_label.pack(side=tk.LEFT, padx=20, pady=15)
        
        back_button = tk.Button(header_frame, text="← Back", font=FONT_FAMILY,
                               bg="#FFFFFF", fg="#000000",
                               activebackground=WARNING_COLOR, activeforeground="#000000",
                               relief=tk.FLAT, bd=0,
                               command=lambda: controller.show_frame(ModeScreen))
        back_button.pack(side=tk.RIGHT, padx=20, pady=15)

        # Create main content area with activity log taking more space
        main_frame = tk.Frame(self, bg=BG_COLOR)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        main_frame.grid_rowconfigure(0, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)  # Left column
        main_frame.grid_columnconfigure(1, weight=3)  # Right column (activity log) gets more space
        
        # Left side - status and progress (smaller)
        left_frame = tk.Frame(main_frame, bg=BG_COLOR)
        left_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        left_frame.grid_columnconfigure(0, weight=1)
        
        # Right side - activity log (larger)
        right_frame = tk.Frame(main_frame, bg=BG_COLOR)
        right_frame.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        right_frame.grid_columnconfigure(0, weight=1)
        right_frame.grid_rowconfigure(0, weight=1)

        # Status section
        status_frame = tk.Frame(left_frame, bg=FRAME_BG, relief=tk.FLAT, bd=0)
        status_frame.grid(row=0, column=0, sticky="ew", pady=(0, 15))
        status_frame.grid_columnconfigure(0, weight=1)
        
        status_header = tk.Label(status_frame, text="CONNECTION STATUS", font=HEADER_FONT,
                                fg=FG_COLOR, bg=FRAME_BG)
        status_header.grid(row=0, column=0, sticky="w", padx=15, pady=(15, 5))
        
        status_inner_frame = tk.Frame(status_frame, bg=FRAME_BG)
        status_inner_frame.grid(row=1, column=0, sticky="ew", padx=15, pady=(0, 15))
        status_inner_frame.grid_columnconfigure(0, weight=1)
        
        self.status_label = tk.Label(status_inner_frame, text="Listening for incoming transfers...", 
                                    font=FONT_FAMILY, fg=SUCCESS_COLOR, bg=FRAME_BG)
        self.status_label.grid(row=0, column=0, sticky="w")

        # Progress section
        progress_frame = tk.Frame(left_frame, bg=FRAME_BG, relief=tk.FLAT, bd=0)
        progress_frame.grid(row=1, column=0, sticky="nsew")
        progress_frame.grid_columnconfigure(0, weight=1)
        
        progress_header = tk.Label(progress_frame, text="TRANSFER PROGRESS", font=HEADER_FONT,
                                  fg=FG_COLOR, bg=FRAME_BG)
        progress_header.grid(row=0, column=0, sticky="w", padx=15, pady=(15, 5))
        
        progress_inner_frame = tk.Frame(progress_frame, bg=FRAME_BG)
        progress_inner_frame.grid(row=1, column=0, sticky="ew", padx=15, pady=(0, 15))
        progress_inner_frame.grid_columnconfigure(0, weight=1)
        
        self.progress = ttk.Progressbar(progress_inner_frame, mode='determinate',
                                       style="Horizontal.TProgressbar")
        self.progress.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        self.speed_label = tk.Label(progress_inner_frame, text="Waiting for transfer", 
                                   font=FONT_FAMILY, fg="#AAAAAA", bg=FRAME_BG)
        self.speed_label.grid(row=1, column=0, pady=(0, 15))
        
        # Control buttons
        control_frame = tk.Frame(progress_inner_frame, bg=FRAME_BG)
        control_frame.grid(row=2, column=0, sticky="ew")
        control_frame.grid_columnconfigure(0, weight=1)
        control_frame.grid_columnconfigure(1, weight=1)
        
        self.pause_button = tk.Button(control_frame, text="Pause", font=FONT_FAMILY,
                                     bg="#FFFFFF", fg="#000000",
                                     activebackground=WARNING_COLOR, activeforeground="#000000",
                                     relief=tk.FLAT, bd=0,
                                     command=self.toggle_pause, state=tk.DISABLED)
        self.pause_button.grid(row=0, column=0, padx=(0, 10), sticky="ew")
        
        self.stop_button = tk.Button(control_frame, text="Stop", font=FONT_FAMILY,
                                    bg="#FFFFFF", fg="#000000",
                                    activebackground=HIGHLIGHT_COLOR, activeforeground="#000000",
                                    relief=tk.FLAT, bd=0,
                                    command=self.stop_receiving, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, sticky="ew")

        # Logs section on the right side (takes more space)
        log_frame = tk.Frame(right_frame, bg=FRAME_BG, relief=tk.FLAT, bd=0)
        log_frame.grid(row=0, column=0, sticky="nsew")
        log_frame.grid_columnconfigure(0, weight=1)
        log_frame.grid_rowconfigure(1, weight=1)
        
        log_header = tk.Label(log_frame, text="ACTIVITY LOG", font=HEADER_FONT,
                             fg=FG_COLOR, bg=FRAME_BG)
        log_header.grid(row=0, column=0, sticky="w", padx=15, pady=(15, 5))
        
        log_inner_frame = tk.Frame(log_frame, bg=FRAME_BG)
        log_inner_frame.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))
        log_inner_frame.grid_columnconfigure(0, weight=1)
        log_inner_frame.grid_rowconfigure(0, weight=1)
        
        log_text = tk.Text(log_inner_frame, font=FONT_FAMILY,
                          bg="#383838", fg=FG_COLOR, 
                          relief=tk.FLAT, bd=0,
                          wrap=tk.WORD,
                          padx=10, pady=10)
        log_text.grid(row=0, column=0, sticky="nsew")
        
        log_scrollbar = tk.Scrollbar(log_inner_frame, orient=tk.VERTICAL, command=log_text.yview,
                                    bg=FRAME_BG, troughcolor=DARK_BG, activebackground=ACCENT_COLOR)
        log_scrollbar.grid(row=0, column=1, sticky="ns")
        log_text.config(yscrollcommand=log_scrollbar.set)
        
        # Initialize receiver logger (separate from sender)
        self.receiver_logger = Logger(log_text)
        
        # Initialize discovery only if not already done (shared between sender and receiver)
        if not controller.discovery:
            controller.discovery = PeerDiscovery(self.receiver_logger, name=socket.gethostname())
            controller.discovery.start()
            
        # Initialize receiver with our progress bar and speed label
        controller.receiver = Receiver(self.receiver_logger, self.status_label,
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
                            # Format file size in human readable format
                            if int(filesize) < 1024:
                                size_str = f"{filesize} B"
                            elif int(filesize) < 1024 * 1024:
                                size_str = f"{int(filesize) // 1024} KB"
                            elif int(filesize) < 1024 * 1024 * 1024:
                                size_str = f"{int(filesize) // (1024 * 1024)} MB"
                            else:
                                size_str = f"{int(filesize) // (1024 * 1024 * 1024)} GB"
                            
                            res = messagebox.askyesno(
                                "Incoming File",
                                f"{addr[0]} wants to send '{filename}' ({size_str}).\n\nAccept this transfer?"
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
            # Provide a better default path for Linux compatibility
            default_dir = os.path.expanduser("~/Downloads")
            if not os.path.exists(default_dir):
                default_dir = os.path.expanduser("~")
            default_path = os.path.join(default_dir, default_name)
            return filedialog.asksaveasfilename(initialfile=default_name, initialdir=default_dir)
        self.controller.receiver.download(ip, sender_port, ask_save, None)
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