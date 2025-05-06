import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from ftplib import FTP
import time
import sched
import socket
import sys
from scapy.all import sr, IP, ICMP,conf
from ipaddress import ip_address

host= "127.0.0.1"
port = 2121
conf.use_pcap = False
conf.verb = 0

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def port_scanner():
    clear_screen()
    ip = input("Please enter a target IP !")
    port_range = input("Please enter a port range !")
    if not ip:
        print("You could not enter IP.")
    if not port_range:
        print("You could not enter Port range.")    
        
    try:    
        start_port, end_port = map(int, port_range.split('-'))    
        print(f"On {ip}'s port searching...")
        open_ports = []
        for port in range(start_port, end_port + 1):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    service = socket.getservbyport(port)
                    open_ports.append(port)
                    print(f"Port {port}: {service} : Open")
                sock.close()
        print("It's done.")
    except Exception as e:
        print(f"Error: {e}")    
    input("Please press any key to continue...")            

def web_crawler():
    clear_screen()
    url = input("Enter URL (e.g. https://example.com): ").strip()
    keyword = input("Enter the word to search : ").strip()

    if not url:
        print("Error: Please enter a URL")
        input("Please press any key to continue...")
        return

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        print(f"{url} processing...")
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        text = response.text
        soup = BeautifulSoup(text, 'html.parser')

        for link in soup.find_all("a"):
            href = link.get("href")
            if href:
                full_url = urljoin(url, href)
            try:
                r = requests.head(full_url, allow_redirects=True, timeout=5)
                if r.status_code >= 400:
                    print(f"Broken link: {full_url} (Status: {r.status_code})")
            except:
                print(f"Failed to check: {full_url}")
        
        if keyword:
            if keyword.lower() in text.lower():
                print(f"Word: '{keyword}' found on the page!")
            else:
                print(f"Word: '{keyword}' not found on page...")
        else:
            print("No keyword specified.")

        links = [a.get('href') for a in soup.find_all('a', href=True)]
        unique_links = list(set(links))
        print("\nFound Links:")
        if unique_links:
            for link in unique_links:
                print(link)
        else:
            print("No links found.")

        img_dir = "img"
        if not os.path.exists(img_dir):
            os.makedirs(img_dir)

        print("\nDownloading images:")
        for img in soup.find_all("img"):
            src = img.get("src")
            if src:
                img_url = urljoin(url, src)
                filename = os.path.join(img_dir, os.path.basename(src) or f"image_{hash(img_url)}.jpg")
                try:
                    img_data = requests.get(img_url, timeout=5).content
                    with open(filename, "wb") as f:
                        f.write(img_data)
                    print(f"Kaydedildi: {filename}")
                except Exception as e:
                    print(f"İndirilemedi: {img_url} (Hata: {e})")

    except Exception as e:
        print(f"Error: Operation failed: {e}")
    input("Please press any key to continue...")

def file_transfer_client():
    clear_screen()
    ftp_user = "user"
    ftp_pass = "pass"

    try:
        ftp = FTP()
        print(f"Connecting: {host}:{port}...")
        ftp.connect(host, port)
        ftp.login(ftp_user, ftp_pass)
        print("Connection successful!")

        print("Files in server:")
        files = ftp.nlst
        if files:
            for file in files:
                print(file)    

        def download_file(line):
            print(line)
            parts = line.split()
            if len(parts) >= 9:
                files.append(parts[-1])

        ftp.retrlines("LIST", callback=download_file)

        choice = input("\nEnter name of file to download: ")

        if choice in files:
            with open(choice, "wb") as f:
                ftp.retrbinary(f"RETR {choice}", f.write)
            print(f"Downlod success: {choice}.")
        else:
            print("File not found!")

        ftp.quit()
    except Exception as e:
        print(f"Error:  {e})")
    input("Please press any key to continue...")

def file_transfer_server():
    clear_screen()
    try:
        authorizer = DummyAuthorizer()
        authorizer.add_user("user", "pass", "D:/ftpFiles", perm="elradfmw")  
        authorizer.add_anonymous("D:/ftpFiles")  

        handler = FTPHandler
        handler.authorizer = authorizer

        # Start server
        server = FTPServer((host, port), handler)
        server.serve_forever()

    except Exception as e:
        print(f"Hata: {e})")
    input("Please press any key to continue...")    

def data_fetcher():
    clear_screen()
    topic = input("Please Enter a topic!")
    if not topic:
        print("Error: Please enter a topic")
        data_fetcher()
    
    def data_summary(topic):
        try:
            url = f"https://en.wikipedia.org/api/rest_v1/page/summary/{topic.replace(' ', '_')}"
            print("Finding...")
            response = requests.get(url, timeout=20)
            response.raise_for_status()
            data = response.json()
            summary = data.get('extract', 'Summary not found.')
            print(summary)
        except Exception as e:
            print(f"Hata: {e}")

    data_summary(topic)
    input("Please press any key to continue...")

def device_scanner():
    clear_screen()
    RUN_FREQUENCY = 10
    scheduler = sched.scheduler(time.time, time.sleep)

    def parse_ip_range(ip_range_str):
        try:
            if '-' in ip_range_str:
                base_ip, range_part = ip_range_str.rsplit('.', 1)
                start, end = map(int, range_part.split('-'))
                return [f"{base_ip}.{i}" for i in range(start, end + 1)]
            else:
                return [ip_range_str]
        except Exception as e:
            print(f"Hata: {e}")
            return []

    def detect_inactive_hosts(scan_hosts):
        scheduler.enter(RUN_FREQUENCY, 1, detect_inactive_hosts, (scan_hosts,))
        inactive_hosts = []
        try:
            target_list = parse_ip_range(scan_hosts)
            ans, unans = sr(IP(dst=target_list)/ICMP(), retry=0, timeout=1)
            ans.summary(lambda s, r: print(f"{r[IP].src} is alive"))
            for inactive in unans:
                print(f"{inactive.dst} is inactive")
                inactive_hosts.append(inactive.dst)

            print(f"Total {len(inactive_hosts)} hosts are inactive")

        except KeyboardInterrupt:
            sys.exit(0)

    scan_hosts = input("Please enter the Ip range (e.g. 192.168.1.1-5 or 192.168.1.1): ").strip()
    if not scan_hosts:
        print("Error: You did not enter an IP range")
        input("Please press any key to continue...")
        return
    else:
        detect_inactive_hosts(scan_hosts)
        scheduler.run()
    input("Please press any key to continue...")    

def broadcast():
    clear_screen()
    local_network = "255.255.255.255"
    port = 5555
    msg = input("Enter your message ! ")
    if not msg:
        print("Enter your message !")
        broadcast()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(1)    
        broadcast_address = (local_network,port)
        sock.sendto(msg.encode(), broadcast_address)
        print("Message sent:", msg)
        sock.close()
    except Exception as e: 
        print(f"Error: {e}")   
    input("Please press any key to continue...")    

def main_menu():
    while True:
        clear_screen()
        print("=== Network Toolkit ===")
        print("1. Port Scanner")
        print("2. Web Crawler")
        print("3. File Transfer Client")
        print("4. File Transfer Server")
        print("5. Wikipedia Data Fetcher")
        print("6. Network Device Scanner")
        print("7. Broadcast Messaging")
        print("8. Çıkış")
        choice = input("Please make your choice (1-8):").strip()

        if choice == '1':
            port_scanner()
        elif choice == '2':
            web_crawler()
        elif choice == '3':
            file_transfer_client()
        elif choice == '4':
            file_transfer_server()
        elif choice == '5':
            data_fetcher()
        elif choice == '6':
            device_scanner()
        elif choice == '7':
            broadcast()
        elif choice == '8':
            print("Çıkılıyor...")
            break
        else:
            print("Error invalid selection.")
            input("Please press any key to continue...")

if __name__ == "__main__":
    main_menu()