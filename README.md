Network Toolkit GUI
Overview
Network Toolkit GUI is a Python-based application providing a suite of network tools through a user-friendly graphical interface. Built with customtkinter, it supports port scanning, web crawling, file transfers, Wikipedia data fetching, device scanning, and broadcast messaging.
Features

Port Scanner: Scan open ports on a target IP.
Web Crawler: Extract links and search keywords on a website.
File Transfer Client/Server: FTP-based file upload/download.
Wikipedia Fetcher: Retrieve summaries from Wikipedia.
Device Scanner: Detect active/inactive devices in a network.
Broadcast Messaging: Send/receive UDP broadcast messages.
History: Log all actions with export capability.
Settings: Configure FTP directory.

Requirements

Python 3.9+
Libraries:
customtkinter
requests
beautifulsoup4
pyftpdlib
scapy
tkinter (included with Python)

Install dependencies:pip install customtkinter requests beautifulsoup4 pyftpdlib scapy


Ensure C:/ftpFiles directory exists for FTP operations or update ftp_config in the code.

Usage

Run the application:
py PartAGUI.py

Use the GUI to navigate tabs:

Port Scanner: Enter IP and port range (e.g., 192.168.1.1, 20-80).
Web Crawler: Input URL and optional keyword.
File Transfer: Start server, then use client to upload/download files.
Wikipedia Fetcher: Enter a topic (e.g., Python).
Device Scanner: Specify IP range (e.g., 192.168.1.1-5).
Broadcast Messaging: Send/receive messages on port 5555.
History: View/export logs.
Settings: Set FTP directory.

Close the application using the window's close button.

Notes

Firewall: Allow UDP port 5555 for broadcast messaging.netsh advfirewall firewall add rule name="UDP 5555" dir=in action=allow protocol=UDP localport=5555


Permissions: Run with admin privileges for device scanning.
Logs: Broadcast messages are saved to broadcast_log.txt.

Troubleshooting

Port Conflicts: Check port 5555 or 2121 with netstat -ano | findstr <port>.
Network Issues: Use subnet broadcast (e.g., 192.168.1.255) if 255.255.255.255 fails.
Errors: Ensure all dependencies are installed and paths are correct.

