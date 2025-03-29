import random
import subprocess
import concurrent.futures
import socket
import requests
import whois

try:
    from scapy.all import sr1, IP, ICMP  # Fast ICMP ping
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False  # Fallback to normal ping

# --- CONFIGURABLE OPTIONS ---
USE_SCAPY = True  # Use Scapy for faster ICMP requests (requires installation)
STEALTH_MODE = False  # Check ports instead of pinging
FILTER_VPN = True  # Only show real user IPs (not datacenters)
SHOW_ONLY_ONLINE = True  # Hide offline IPs
PORTS_TO_CHECK = [80, 443, 22]  # Ports to check in stealth mode

# Public IP Ranges (avoiding reserved/private ones)
PUBLIC_IP_RANGES = [
    (1, 223),  # Avoid 224-255 (reserved/multicast)
    (0, 255),
    (0, 255),
    (1, 254)  # Avoid 0 and 255 (network/broadcast)
]

def generate_ip():
    """Generates a random public IPv4 address."""
    return ".".join(str(random.randint(r[0], r[1])) for r in PUBLIC_IP_RANGES)

def ping_ip(ip):
    """Pings an IP using Scapy (if enabled) or subprocess."""
    if USE_SCAPY and SCAPY_AVAILABLE:
        packet = IP(dst=ip) / ICMP()
        response = sr1(packet, timeout=1, verbose=0)
        return ip if response else None
    else:
        try:
            result = subprocess.run(["ping", "-n", "1", "-w", "1000", ip],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return ip if result.returncode == 0 else None
        except Exception:
            return None

def check_open_ports(ip):
    """Checks if any specified ports are open (Stealth Mode)."""
    for port in PORTS_TO_CHECK:
        try:
            sock = socket.create_connection((ip, port), timeout=1)
            sock.close()
            return ip  # Found an open port
        except (socket.timeout, ConnectionRefusedError):
            pass
    return None  # No open ports found

def is_vpn_or_proxy(ip):
    """Checks if an IP is from a VPN or datacenter using WHOIS lookup."""
    try:
        domain_info = whois.whois(ip)
        if any(keyword in str(domain_info) for keyword in ["Cloudflare", "Amazon", "Google", "DigitalOcean", "OVH", "Hetzner"]):
            return True  # IP is from a known VPN/datacenter
    except:
        pass
    return False  # Probably a real user

def scan_ips(count=50, threads=10):
    """Scans multiple IPs using multithreading."""
    active_ips = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        ip_list = [generate_ip() for _ in range(count)]
        check_function = check_open_ports if STEALTH_MODE else ping_ip
        future_to_ip = {executor.submit(check_function, ip): ip for ip in ip_list}

        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            if future.result():
                if FILTER_VPN and is_vpn_or_proxy(ip):
                    print(f"❌ VPN/Datacenter: {ip}")
                    continue
                print(f"✅ Online: {ip}")
                active_ips.append(ip)
            elif not SHOW_ONLY_ONLINE:
                print(f"❌ Offline: {ip}")

    return active_ips

# Run the optimized scan
if __name__ == "__main__":
    print("Scanning for active IPs...")
    active_ips = scan_ips(count=100, threads=20)
    print("\nActive IPs Found:", active_ips if active_ips else "None")
