import socket
import socketserver
import http.server
import pyftpdlib.authorizers
import pyftpdlib.servers
import threading
import logging
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta
import os
import random

# Global Variables
ssh_attempts = []
http_requests = []
ftp_access = []
telnet_access = []
blocked_ips = {}

# Logging Configuration
logging.basicConfig(filename='honeypot.log', level=logging.INFO, format='%(asctime)s %(message)s')
logger = logging.getLogger()

# Email Alerting Configuration
SMTP_SERVER = "your_smtp_server"
FROM_EMAIL = "your_email"
PASSWORD = "your_password"

# --- SSH Honeypot ---
class SSHServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

class SSHHandler(socketserver.BaseRequestHandler):
    def handle(self):
        global ssh_attempts, blocked_ips
        ip = self.client_address[0]
        if ip in blocked_ips and blocked_ips[ip] > datetime.now():
            self.request.close()
            return
        ssh_attempts.append({
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'rc_ip': ip
        })
        logger.info(f"SSH Attempt: {ip}")
        self.request.sendall(b"SSH-2.0-Server Ready")
        data = self.request.recv(1024).decode()
        if "login" in data.lower():
            self.request.sendall(b"Username: ")
            username = self.request.recv(1024).decode()
            self.request.sendall(b"Password: ")
            password = self.request.recv(1024).decode()
            logger.info(f"SSH Login Attempt: {ip} - User: {username}, Pass: {password}")
            if random.random() < 0.5: # 50% chance to block after a login attempt
                blocked_ips[ip] = datetime.now() + timedelta(minutes=30)
                logger.warning(f"IP Blocked for 30 minutes: {ip}")
                send_alert(f"SSH Login Attempt from {ip} - Blocked")
        self.request.close()

# --- HTTP Honeypot ---
class HTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        global http_requests
        http_requests.append({
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'rc_ip': self.client_address[0],
            'equest': self.requestline
        })
        logger.info(f"HTTP Request: {self.client_address[0]} - {self.requestline}")
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Welcome to Our Site</h1></body></html>")
        elif self.path == "/about":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>About Us</h1></body></html>")
        else:
            self.send_response(404)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Not Found</h1></body></html>")

    def do_POST(self):
        global http_requests
        content_length = int(self.headers['Content-Length'])
        post_body = self.rfile.read(content_length)
        http_requests.append({
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'rc_ip': self.client_address[0],
            'equest': self.requestline,
            'post_data': post_body.decode()
        })
        logger.info(f"HTTP POST Request: {self.client_address[0]} - {self.requestline} - Data: {post_body.decode()}")
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>POST Received</h1></body></html>")

# --- FTP Honeypot ---
class FTPHandler(pyftpdlib.ftpserver.FTPHandler):
    authorizer = pyftpdlib.authorizers.DummyAuthorizer()
    authorizer.add_user("test", "test", "/tmp", perm="elradfmw")
    authorizer.add_anonymous("/tmp")

    def on_login(self, ftp_connection):
        global ftp_access
        ftp_access.append({
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'rc_ip': ftp_connection.sock.getpeername()[0]
        })
        logger.info(f"FTP Login: {ftp_connection.sock.getpeername()[0]}")

    def on_logout(self, ftp_connection):
        logger.info(f"FTP Logout: {ftp_connection.sock.getpeername()[0]}")

    def on_upload(self, ftp_connection, file_name, file_path):
        logger.info(f"FTP Upload: {ftp_connection.sock.getpeername()[0]} - File: {file_name}")

# --- Telnet Honeypot (Decoy) ---
class TelnetHandler(socketserver.BaseRequestHandler):
    def handle(self):
        global telnet_access
        telnet_access.append({
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'rc_ip': self.client_address[0]
        })
        logger.info(f"Telnet Attempt: {self.client_address[0]}")
        self.request.sendall(b"Login: ")
        self.request.recv(1024)
        self.request.sendall(b"Password: ")
        self.request.recv(1024)
        self.request.close()

# --- Main Program ---
if __name__ == "__main__":
    print("Starting Advanced Honeypot Services...")
    
    # SSH Service
    ssh_server = SSHServer(('0.0.0.0', 2222), SSHHandler)
    ssh_server_thread = threading.Thread(target=ssh_server.serve_forever)
    ssh_server_thread.daemon = True
    ssh_server_thread.start()
    
    # HTTP Service
    http_server = http.server.HTTPServer(('0.0.0.0', 8080), HTTPRequestHandler)
    http_server_thread = threading.Thread(target=http_server.serve_forever)
    http_server_thread.daemon = True
    http_server_thread.start()
    
    # FTP Service
    ftp_server = pyftpdlib.servers.FTPServer(('0.0.0.0', 2121), FTPHandler)
    ftp_server_thread = threading.Thread(target=ftp_server.serve_forever)
    ftp_server_thread.daemon = True
    ftp_server_thread.start()
    
    # Telnet Decoy Service
    telnet_server = socketserver.TCPServer(('0.0.0.0', 2323), TelnetHandler)
    telnet_server_thread = threading.Thread(target=telnet_server.serve_forever)
    telnet_server_thread.daemon = True
    telnet_server_thread.start()
    
    # Simulate System Reboots
    def simulate_reboot():
        while True:
            logger.info("Simulating System Reboot...")
            os.system('sleep 3600') # 1 hour
            # Here you could add commands to simulate a reboot, e.g., restarting services
            
    reboot_thread = threading.Thread(target=simulate_reboot)
    reboot_thread.daemon = True
    reboot_thread.start()
    
    print("Advanced Honeypot Started. Listening on Ports: SSH(2222), HTTP(8080), FTP(2121), Telnet(2323)")
    print("Press Ctrl+C to Quit...")
    
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\nStopping Honeypot...")
        ssh_server.shutdown()
        http_server.shutdown()
        ftp_server.shutdown()
        telnet_server.shutdown()
        print("Honeypot Stopped. Logs:")
        print("SSH Attempts:", ssh_attempts)
        print("HTTP Requests:", http_requests)
        print("FTP Access:", ftp_access)
        print("Telnet Attempts:", telnet_access)

# --- Email Alert Function ---
def send_alert(message):
    msg = EmailMessage()
    msg.set_content(message)
    msg['subject'] = "Honeypot Alert"
    msg['to'] = "recipient_email@example.com"
    msg['from'] = FROM_EMAIL
    
    with smtplib.SMTP_SSL(SMTP_SERVER, 465) as smtp:
        smtp.login(FROM_EMAIL, PASSWORD)
        smtp.send_message(msg)
    print("Alert Email Sent!")
