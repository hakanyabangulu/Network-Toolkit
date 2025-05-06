import os
import requests
import socket
import threading
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from ftplib import FTP
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from datetime import datetime
from scapy.all import sr, IP, ICMP, conf
import customtkinter as ctk
from tkinter import scrolledtext, messagebox, filedialog
import tkinter as tk

conf.use_pcap = False  # Disable pcap for Scapy
conf.verb = 0  # Turn off Scapy verbose
ctk.set_appearance_mode("dark")  # Set dark theme
ctk.set_default_color_theme("blue")  # Set blue theme

class TabBase:
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        self.frame = ctk.CTkFrame(self.parent)  # Create frame
        self.frame.pack(fill="both", expand=True, padx=10, pady=10)  # Pack frame

class NetworkToolkitGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Toolkit Pro")  # Set window title
        self.root.geometry("1200x600")  # Set window size
        self.server_thread = None
        self.server = None
        self.history = []  # Store history
        self.input_history = {
            "port_scanner_ip": [], "port_scanner_range": [], "web_crawler_url": [],
            "web_crawler_keyword": [], "data_fetcher_topic": [], "device_scanner_hosts": [],
            "broadcast_msg": [], "ftp_directory": []
        }  # Store input history
        self.ftp_config = {"host": "127.0.0.1", "port": 2121, "user": "user", "pass": "pass", "dir": "C:/ftpFiles"}  # FTP config
        self.receiver_running = False  # Receiver state

        self.create_widgets()  # Setup GUI
        self.root.bind("<Control-s>", lambda e: self.simulate_action_button())  # Bind Ctrl+S
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)  # Handle window close

    def create_widgets(self):
        self.status_frame = ctk.CTkFrame(self.root)  # Create status frame
        self.status_frame.pack(fill="x", padx=10, pady=5)  # Pack status frame
        self.status_label = ctk.CTkLabel(self.status_frame, text="Ready", font=("Arial", 14))  # Status label
        self.status_label.pack(side="left", padx=10)  # Pack status label
        self.clock_label = ctk.CTkLabel(self.status_frame, text="", font=("Arial", 14))  # Clock label
        self.clock_label.pack(side="right", padx=10)  # Pack clock label
        self.update_clock()  # Start clock

        self.main_frame = ctk.CTkFrame(self.root)  # Create main frame
        self.main_frame.pack(pady=10, padx=10, fill="both", expand=True)  # Pack main frame

        self.notebook = ctk.CTkTabview(self.main_frame)  # Create tab view
        self.notebook.pack(pady=10, fill="both", expand=True)  # Pack tab view

        self.tabs = {
            "Port Scanner": self.notebook.add("🔍 Port Scanner"),
            "Web Crawler": self.notebook.add("🌐 Web Crawler"),
            "File Transfer Client": self.notebook.add("⬇️ File Transfer Client"),
            "File Transfer Server": self.notebook.add("⬆️ File Transfer Server"),
            "Wikipedia Fetcher": self.notebook.add("📚 Wikipedia Fetcher"),
            "Device Scanner": self.notebook.add("🖧 Device Scanner"),
            "Broadcast Messaging": self.notebook.add("📡 Broadcast Messaging"),
            "Broadcast Receiver": self.notebook.add("📥 Broadcast Receiver"),
            "History": self.notebook.add("📜 History"),
            "Settings": self.notebook.add("⚙️ Settings")
        }  # Define tabs

        self.setup_tabs()  # Setup tab content

    def update_clock(self):
        self.clock_label.configure(text=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))  # Update clock
        self.root.after(1000, self.update_clock)  # Schedule next update

    def log_to_history(self, tab_name, output):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Get timestamp
        self.history.append(f"[{timestamp}] {tab_name}:\n{output}\n{'-'*50}")  # Add to history
        if "History" in self.tabs and hasattr(self.tabs["History"], "history_text"):
            self.update_history_tab()  # Update history tab

    def update_history_tab(self):
        history_text = self.tabs["History"].history_text
        history_text.delete(1.0, tk.END)  # Clear history text
        history_text.insert(tk.END, "\n".join(self.history) + "\n")  # Insert history

    def save_input(self, key, value):
        if value and key and value not in self.input_history[key]:
            self.input_history[key].append(value)  # Add to history
            if len(self.input_history[key]) > 5:
                self.input_history[key].pop(0)  # Limit history

    def create_input_field(self, frame, label_text, history_key, row, col=0, width=200, placeholder=None):
        ctk.CTkLabel(frame, text=label_text, font=("Arial", 14)).grid(row=row, column=col, padx=10, pady=5, sticky="e")  # Create label
        if not history_key:
            entry = ctk.CTkEntry(frame, width=width, placeholder_text=placeholder)  # Create entry
        else:
            entry = ctk.CTkComboBox(frame, width=width, values=self.input_history[history_key])  # Create combobox
        entry.grid(row=row, column=col+1, padx=10, pady=5)  # Pack entry
        if history_key:
            entry.bind("<KeyRelease>", lambda e: self.save_input(history_key, entry.get()))  # Bind input save
        return entry

    def create_output_text(self, frame, row, col=0, height=15, width=80):
        output = scrolledtext.ScrolledText(frame, height=height, width=width, font=("Arial", 12))  # Create text area
        output.grid(row=row, column=col, columnspan=2, padx=10, pady=10)  # Pack text area
        output.tag_configure("success", foreground="green")  # Success style
        output.tag_configure("error", foreground="red")  # Error style
        return output

    def create_progress_bar(self, frame):
        return ctk.CTkProgressBar(frame, mode="indeterminate")  # Create progress bar

    def run_with_progress(self, func, args, status_message, tab_name, progress_bar):
        self.status_label.configure(text=status_message)  # Update status
        self.root.config(cursor="wait")  # Set wait cursor
        progress_bar.grid(row=4, column=0, columnspan=2, pady=5)  # Show progress bar
        progress_bar.start()  # Start progress
        try:
            func(*args)  # Run function
        except Exception as e:
            args[-1].insert(tk.END, f"Error: {e}\n", "error")  # Show error
        finally:
            progress_bar.stop()  # Stop progress
            progress_bar.grid_forget()  # Hide progress bar
            output = args[-1].get(1.0, tk.END).strip()  # Get output
            self.log_to_history(tab_name, output)  # Log output
            self.status_label.configure(text="Ready")  # Reset status
            self.root.config(cursor="")  # Reset cursor

    def simulate_action_button(self):
        current_tab = self.notebook.get()  # Get current tab
        tab = self.tabs.get(current_tab)
        if hasattr(tab, "action_button"):
            tab.action_button.invoke()  # Trigger action

    def get_ftp_files(self):
        files = []  # Store files
        try:
            with FTP() as ftp:
                ftp.connect(self.ftp_config["host"], self.ftp_config["port"])  # Connect FTP
                ftp.login(self.ftp_config["user"], self.ftp_config["pass"])  # Login FTP
                ftp.retrlines("LIST", lambda line: files.append(line.split()[-1]) if not line.startswith('d') else None)  # List files
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch file list: {e}")  # Show error
        return files

    def upload_file(self, output_text):
        file_path = filedialog.askopenfilename()  # Open file dialog
        if not file_path:
            return
        try:
            with FTP() as ftp:
                ftp.connect(self.ftp_config["host"], self.ftp_config["port"])  # Connect FTP
                ftp.login(self.ftp_config["user"], self.ftp_config["pass"])  # Login FTP
                with open(file_path, "rb") as f:
                    ftp.storbinary(f"STOR {os.path.basename(file_path)}", f)  # Upload file
                output_text.insert(tk.END, f"Upload successful: {os.path.basename(file_path)}\n", "success")  # Show success
        except Exception as e:
            output_text.insert(tk.END, f"Error: {e}\n", "error")  # Show error

    def stop_server(self):
        if self.server:
            self.server.close_all()  # Close server
            self.server = None
            self.status_label.configure(text="Server stopped")  # Update status
            if "File Transfer Server" in self.tabs:
                self.tabs["File Transfer Server"].output_server.insert(tk.END, "Server stopped\n", "success")  # Show stop
                self.log_to_history("File Transfer Server", "Server stopped")  # Log stop

    def export_log(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])  # Save dialog
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write("\n".join(self.history))  # Write history
            messagebox.showinfo("Success", "Log exported successfully")  # Show success

    def start_receiver(self, output_text):
        if hasattr(self, "receiver_thread") and self.receiver_thread.is_alive():
            output_text.insert(tk.END, "Receiver already running\n", "error")  # Check running
            return
        self.receiver_running = True  # Set running
        self.receiver_thread = threading.Thread(target=self.run_receiver, args=(output_text,), daemon=True)  # Create thread
        self.receiver_thread.start()  # Start thread
        output_text.insert(tk.END, "Receiver started on port 5555\n", "success")  # Show start

    def stop_receiver(self, output_text):
        if not hasattr(self, "receiver_running") or not self.receiver_running:
            if output_text:
                output_text.insert(tk.END, "Receiver not running\n", "error")  # Show error
            else:
                print("Receiver not running")  # Log to console
            return
        self.receiver_running = False  # Stop running
        if output_text:
            output_text.insert(tk.END, "Receiver stopped\n", "success")  # Show stop
        else:
            print("Receiver stopped")  # Log to console

    def on_closing(self):
        self.stop_server()  # Stop FTP server
        if "Broadcast Receiver" in self.tabs and hasattr(self.tabs["Broadcast Receiver"], "output_receiver"):
            self.stop_receiver(self.tabs["Broadcast Receiver"].output_receiver)  # Stop receiver
        else:
            self.receiver_running = False  # Ensure receiver stops
            print("No receiver output, stopping receiver")  # Log to console
        self.root.destroy()  # Close window

    def run_receiver(self, output_text):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Create UDP socket
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow address reuse
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)  # Enable broadcast
        try:
            sock.bind(('', 5555))  # Bind to port 5555
        except Exception as e:
            output_text.insert(tk.END, f"Error binding to port 5555: {e}\n", "error")  # Bind error
            sock.close()
            return
        try:
            while self.receiver_running:
                data, addr = sock.recvfrom(1024)  # Receive message
                output_text.insert(tk.END, f"Received: {data.decode('utf-8')} from {addr}\n", "success")  # Show message
                output_text.see(tk.END)  # Scroll to end
        except Exception as e:
            if self.receiver_running:
                output_text.insert(tk.END, f"Error: {e}\n", "error")  # Show error
        finally:
            sock.close()  # Close socket

    def setup_tabs(self):
        # Port Scanner
        port_tab = TabBase(self.tabs["Port Scanner"], self)
        ip_entry = self.create_input_field(port_tab.frame, "Target IP*:", "port_scanner_ip", 0)  # IP input
        port_range_entry = self.create_input_field(port_tab.frame, "Port Range (e.g., 20-80)*:", "port_scanner_range", 1)  # Range input
        output_port = self.create_output_text(port_tab.frame, 2)  # Output area
        progress_bar = self.create_progress_bar(port_tab.frame)  # Progress bar
        scan_button = ctk.CTkButton(port_tab.frame, text="Scan", command=lambda: self.run_with_progress(port_scanner, [ip_entry.get(), port_range_entry.get(), output_port], "Scanning ports...", "Port Scanner", progress_bar))  # Scan button
        scan_button.grid(row=3, column=0, columnspan=2, pady=10)  # Pack button
        port_tab.action_button = scan_button
        ctk.CTkLabel(port_tab.frame, text="Enter IP like 192.168.1.1", font=("Arial", 10)).grid(row=0, column=2, padx=5)  # IP hint
        ctk.CTkLabel(port_tab.frame, text="Enter range like 20-80", font=("Arial", 10)).grid(row=1, column=2, padx=5)  # Range hint

        # Web Crawler
        web_tab = TabBase(self.tabs["Web Crawler"], self)
        url_entry = self.create_input_field(web_tab.frame, "URL*:", "web_crawler_url", 0)  # URL input
        keyword_entry = self.create_input_field(web_tab.frame, "Keyword:", "web_crawler_keyword", 1)  # Keyword input
        output_web = self.create_output_text(web_tab.frame, 2)  # Output area
        progress_bar = self.create_progress_bar(web_tab.frame)  # Progress bar
        scan_button = ctk.CTkButton(web_tab.frame, text="Scan", command=lambda: self.run_with_progress(web_crawler, [url_entry.get(), keyword_entry.get(), output_web], "Crawling web...", "Web Crawler", progress_bar))  # Scan button
        scan_button.grid(row=3, column=0, columnspan=2, pady=10)  # Pack button
        web_tab.action_button = scan_button
        ctk.CTkLabel(web_tab.frame, text="Enter URL like https://example.com", font=("Arial", 10)).grid(row=0, column=2, padx=5)  # URL hint

        # File Transfer Client
        client_tab = TabBase(self.tabs["File Transfer Client"], self)
        choice_combo = ctk.CTkComboBox(client_tab.frame, width=200, values=["Connect to refresh"])  # File selector
        ctk.CTkLabel(client_tab.frame, text="Select File:", font=("Arial", 14)).grid(row=0, column=0, padx=10, pady=5, sticky="e")  # File label
        choice_combo.grid(row=0, column=1, padx=10, pady=5)  # Pack selector
        output_client = self.create_output_text(client_tab.frame, 1, col=0, width=80)  # Output area
        def update_file_list():
            files = self.get_ftp_files()  # Fetch files
            choice_combo.configure(values=files if files else ["No files found"])  # Update selector
        ctk.CTkButton(client_tab.frame, text="Refresh File List", command=update_file_list).grid(row=2, column=0, padx=10, pady=5)  # Refresh button
        ctk.CTkButton(client_tab.frame, text="Download", command=lambda: self.run_with_progress(file_transfer_client, [output_client, choice_combo.get(), self.ftp_config], "Downloading file...", "File Transfer Client", self.create_progress_bar(client_tab.frame))).grid(row=2, column=1, padx=10, pady=5)  # Download button
        ctk.CTkButton(client_tab.frame, text="Upload File", command=lambda: self.upload_file(output_client)).grid(row=2, column=2, padx=10, pady=5)  # Upload button

        # File Transfer Server
        server_tab = TabBase(self.tabs["File Transfer Server"], self)
        output_server = self.create_output_text(server_tab.frame, 0)  # Output area
        server_tab.output_server = output_server
        ctk.CTkButton(server_tab.frame, text="Start Server", command=lambda: self.run_with_progress(file_transfer_server, [output_server, self], "Starting server...", "File Transfer Server", self.create_progress_bar(server_tab.frame))).grid(row=1, column=0, padx=10, pady=5)  # Start button
        ctk.CTkButton(server_tab.frame, text="Stop Server", command=self.stop_server).grid(row=1, column=1, padx=10, pady=5)  # Stop button

        # Wikipedia Fetcher
        data_tab = TabBase(self.tabs["Wikipedia Fetcher"], self)
        topic_entry = self.create_input_field(data_tab.frame, "Topic*:", "data_fetcher_topic", 0)  # Topic input
        output_data = self.create_output_text(data_tab.frame, 1)  # Output area
        progress_bar = self.create_progress_bar(data_tab.frame)  # Progress bar
        fetch_button = ctk.CTkButton(data_tab.frame, text="Fetch", command=lambda: self.run_with_progress(data_fetcher, [topic_entry.get(), output_data], "Fetching data...", "Wikipedia Fetcher", progress_bar))  # Fetch button
        fetch_button.grid(row=2, column=0, columnspan=2, pady=10)  # Pack button
        data_tab.action_button = fetch_button
        ctk.CTkLabel(data_tab.frame, text="Enter a topic like 'Python'", font=("Arial", 10)).grid(row=0, column=2, padx=5)  # Topic hint

        # Device Scanner
        device_tab = TabBase(self.tabs["Device Scanner"], self)
        scan_hosts_entry = self.create_input_field(device_tab.frame, "IP Range (e.g., 192.168.1.1-5)*:", "device_scanner_hosts", 0)  # IP range input
        output_device = self.create_output_text(device_tab.frame, 1)  # Output area
        progress_bar = self.create_progress_bar(device_tab.frame)  # Progress bar
        scan_button = ctk.CTkButton(device_tab.frame, text="Scan", command=lambda: self.run_with_progress(device_scanner, [scan_hosts_entry.get(), output_device], "Scanning devices...", "Device Scanner", progress_bar))  # Scan button
        scan_button.grid(row=2, column=0, columnspan=2, pady=10)  # Pack button
        device_tab.action_button = scan_button
        ctk.CTkLabel(device_tab.frame, text="Enter range like 192.168.1.1-5", font=("Arial", 10)).grid(row=0, column=2, padx=5)  # Range hint

        # Broadcast Messaging
        broadcast_tab = TabBase(self.tabs["Broadcast Messaging"], self)
        msg_entry = self.create_input_field(broadcast_tab.frame, "Message*:", "broadcast_msg", 0)  # Message input
        output_broadcast = self.create_output_text(broadcast_tab.frame, 1)  # Output area
        progress_bar = self.create_progress_bar(broadcast_tab.frame)  # Progress bar
        send_button = ctk.CTkButton(broadcast_tab.frame, text="Send", command=lambda: self.run_with_progress(broadcast, [msg_entry.get(), output_broadcast], "Sending message...", "Broadcast Messaging", progress_bar))  # Send button
        send_button.grid(row=2, column=0, columnspan=2, pady=10)  # Pack button
        broadcast_tab.action_button = send_button
        ctk.CTkLabel(broadcast_tab.frame, text="Enter a broadcast message", font=("Arial", 10)).grid(row=0, column=2, padx=5)  # Message hint

        # Broadcast Receiver
        receiver_tab = TabBase(self.tabs["Broadcast Receiver"], self)
        output_receiver = self.create_output_text(receiver_tab.frame, 0)  # Output area
        receiver_tab.output_receiver = output_receiver
        start_button = ctk.CTkButton(receiver_tab.frame, text="Start Receiver", command=lambda: self.start_receiver(output_receiver))  # Start button
        start_button.grid(row=1, column=0, padx=10, pady=5)  # Pack start button
        stop_button = ctk.CTkButton(receiver_tab.frame, text="Stop Receiver", command=lambda: self.stop_receiver(output_receiver))  # Stop button
        stop_button.grid(row=1, column=1, padx=10, pady=5)  # Pack stop button
        ctk.CTkLabel(receiver_tab.frame, text="Receives messages on port 5555", font=("Arial", 10)).grid(row=2, column=0, columnspan=2, padx=5)  # Hint label

        # History
        history_tab = TabBase(self.tabs["History"], self)
        history_tab.history_text = self.create_output_text(history_tab.frame, 0)  # Output area
        ctk.CTkButton(history_tab.frame, text="Clear History", command=lambda: [self.history.clear(), self.update_history_tab()]).grid(row=1, column=0, padx=10, pady=5)  # Clear button
        ctk.CTkButton(history_tab.frame, text="Export Log", command=self.export_log).grid(row=1, column=1, padx=10, pady=5)  # Export button

        # Settings
        settings_tab = TabBase(self.tabs["Settings"], self)
        self.create_input_field(settings_tab.frame, "Default FTP Directory:", "", 0, placeholder="C:/ftpFiles")  # FTP dir input

def port_scanner(ip, port_range, output_text):
    output_text.delete(1.0, tk.END)  # Clear output
    if not ip:
        output_text.insert(tk.END, "Error: Please enter an IP address\n", "error")  # Check IP
        return
    if not port_range:
        output_text.insert(tk.END, "Error: Please enter a port range\n", "error")  # Check range
        return
    
    try:
        start_port, end_port = map(int, port_range.split('-'))  # Split range
        output_text.insert(tk.END, f"Scanning ports on {ip}...\n")  # Start scan
        open_ports = []
        for port in range(start_port, end_port + 1):  # Scan ports
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create socket
            sock.settimeout(1)  # Set timeout
            result = sock.connect_ex((ip, port))  # Check port
            if result == 0:  # If open
                try:
                    service = socket.getservbyport(port)  # Get service
                except socket.error:
                    service = "Unknown"  # Unknown service
                open_ports.append(port)
                output_text.insert(tk.END, f"Port {port}: {service} : Open\n", "success")  # Show open port
            sock.close()  # Close socket
        if not open_ports:
            output_text.insert(tk.END, "No open ports found\n")  # No ports
        output_text.insert(tk.END, "Scan completed\n")  # Scan done
    except ValueError:
        output_text.insert(tk.END, "Error: Invalid port range format (use 20-80)\n", "error")  # Format error
    except Exception as e:
        output_text.insert(tk.END, f"Error: {e}\n", "error")  # General error

def web_crawler(url, keyword, output_text):
    output_text.delete(1.0, tk.END)  # Clear output
    if not url:
        output_text.insert(tk.END, "Error: Please enter a URL\n", "error")  # Check URL
        return
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url  # Add https
    try:
        output_text.insert(tk.END, f"Processing {url}...\n")  # Start crawl
        response = requests.get(url, timeout=5)  # Fetch page
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')  # Parse HTML

        for link in soup.find_all("a", href=True):  # Check links
            full_url = urljoin(url, link["href"])
            try:
                r = requests.head(full_url, allow_redirects=True, timeout=5)  # Check link
                if r.status_code >= 400:
                    output_text.insert(tk.END, f"Broken link: {full_url} (Status: {r.status_code})\n", "error")  # Show broken
            except requests.RequestException:
                output_text.insert(tk.END, f"Could not check: {full_url}\n")  # Check failed

        if keyword:  # Search keyword
            output_text.insert(tk.END, f"Keyword '{keyword}' {'found' if keyword.lower() in response.text.lower() else 'not found'} on page!\n", "success" if keyword.lower() in response.text.lower() else "error")
        else:
            output_text.insert(tk.END, "No keyword specified.\n")  # No keyword

        unique_links = list(set(link["href"] for link in soup.find_all("a", href=True)))  # Get unique links
        output_text.insert(tk.END, "\nFound Links:\n" + ("\n".join(unique_links) or "No links found.\n"))  # Show links
    except requests.RequestException as e:
        output_text.insert(tk.END, f"Error: Operation failed: {e}\n", "error")  # Crawl error

def file_transfer_client(output_text, choice, ftp_config):
    output_text.delete(1.0, tk.END)  # Clear output
    files = []
    try:
        with FTP() as ftp:
            output_text.insert(tk.END, f"Connecting to {ftp_config['host']}:{ftp_config['port']}...\n")  # Start connect
            ftp.connect(ftp_config["host"], ftp_config["port"])  # Connect FTP
            ftp.login(ftp_config["user"], ftp_config["pass"])  # Login FTP
            output_text.insert(tk.END, "Connection successful!\n", "success")  # Show success
            ftp.retrlines("LIST", lambda line: files.append(line.split()[-1]) if not line.startswith('d') else None)  # List files
            output_text.insert(tk.END, "Files on server:\n" + "\n".join(files) if files else "Files on server:\nNo files found\n", "success" if files else "error")  # Show files
            if choice and choice != "Connect to refresh" and choice in files:
                with open(choice, "wb") as f:
                    ftp.retrbinary(f"RETR {choice}", f.write)  # Download file
                output_text.insert(tk.END, f"Download successful: {choice}\n", "success")  # Show success
            elif choice and choice != "Connect to refresh":
                output_text.insert(tk.END, "Error: File not found\n", "error")  # File not found
            elif not choice:
                output_text.insert(tk.END, "Error: Please select a file\n", "error")  # No file selected
    except Exception as e:
        output_text.insert(tk.END, f"Error: {e}. Try starting the server on port {ftp_config['port']}.\n", "error")  # FTP error

def file_transfer_server(output_text, app):
    output_text.delete(1.0, tk.END)  # Clear output
    try:
        authorizer = DummyAuthorizer()  # Setup auth
        authorizer.add_user(app.ftp_config["user"], app.ftp_config["pass"], app.ftp_config["dir"], perm="elradfmw")  # Add user
        authorizer.add_anonymous(app.ftp_config["dir"])  # Add anonymous
        handler = FTPHandler
        handler.authorizer = authorizer  # Set handler
        app.server = FTPServer((app.ftp_config["host"], app.ftp_config["port"]), handler)  # Create server
        output_text.insert(tk.END, f"Starting FTP server on {app.ftp_config['host']}:{app.ftp_config['port']}...\n")  # Start server
        app.server_thread = threading.Thread(target=app.server.serve_forever, daemon=True)  # Create thread
        app.server_thread.start()  # Start thread
        output_text.insert(tk.END, "Server running\n", "success")  # Show running
    except Exception as e:
        output_text.insert(tk.END, f"Error: {e}. Ensure port {app.ftp_config['port']} is free.\n", "error")  # Server error

def data_fetcher(topic, output_text):
    output_text.delete(1.0, tk.END)  # Clear output
    if not topic:
        output_text.insert(tk.END, "Error: Please enter a topic\n", "error")  # Check topic
        return
    try:
        output_text.insert(tk.END, "Searching...\n")  # Start search
        response = requests.get(f"https://en.wikipedia.org/api/rest_v1/page/summary/{topic.replace(' ', '_')}", timeout=20)  # Fetch data
        response.raise_for_status()
        summary = response.json().get('extract', 'No summary found.')  # Get summary
        output_text.insert(tk.END, f"{summary}\n", "success")  # Show summary
    except requests.RequestException as e:
        output_text.insert(tk.END, f"Error: {e}\n", "error")  # Fetch error

def device_scanner(scan_hosts, output_text):
    output_text.delete(1.0, tk.END)  # Clear output
    if not scan_hosts:
        output_text.insert(tk.END, "Error: Please enter an IP range\n", "error")  # Check range
        return
    try:
        base_ip, range_part = scan_hosts.rsplit('.', 1) if '-' in scan_hosts else (scan_hosts, '0')  # Split range
        start, end = map(int, range_part.split('-')) if '-' in range_part else (0, 0)  # Get range
        target_list = [f"{base_ip}.{i}" for i in range(start, end + 1)] if '-' in scan_hosts else [scan_hosts]  # Create targets
        ans, unans = sr(IP(dst=target_list)/ICMP(), retry=0, timeout=1)  # Send ICMP
        for s, r in ans:
            output_text.insert(tk.END, f"{r[IP].src} active\n", "success")  # Show active
        for inactive in unans:
            output_text.insert(tk.END, f"{inactive.dst} inactive\n")  # Show inactive
        output_text.insert(tk.END, f"Total {len(unans)} inactive devices\n")  # Show summary
    except Exception as e:
        output_text.insert(tk.END, f"Error: {e}. Ensure you have admin privileges for network scanning.\n", "error")  # Scan error

def broadcast(msg, output_text):
    output_text.delete(1.0, tk.END)  # Clear output
    if not msg:
        output_text.insert(tk.END, "Error: Please enter a message\n", "error")  # Check message
        return
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Get timestamp
        fmessage = f"{timestamp} {msg}"  # Format message
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:  # Create UDP socket
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)  # Enable broadcast
            sock.settimeout(1)  # Set timeout
            sock.sendto(fmessage.encode("utf-8"), ("255.255.255.255", 5555))  # Send message
            output_text.insert(tk.END, f"Message sent: {fmessage}\n", "success")  # Show sent
        with open("broadcast_log.txt", "a", encoding="utf-8") as log:  # Write to log
            log.write(f"{fmessage}\n")
    except Exception as e:
        output_text.insert(tk.END, f"Error: {e}\n", "error")  # Broadcast error

if __name__ == "__main__":
    root = ctk.CTk()  # Create window
    app = NetworkToolkitGUI(root)  # Create app
    root.mainloop()  # Run app