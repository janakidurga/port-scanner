import socket
import threading
import scapy.all as scapy
import matplotlib.pyplot as plt
import streamlit as st
import psutil
import os
import ipaddress
from ipaddress import IPv4Address, IPv6Address, AddressValueError
from visualize import visualize_results, visualize_subnet_results
import time

st.title("🚀 Real-Time Port Scanner & Controller")

st.markdown("""
### ✅ Features of This App
- **Real-time Port Scanning** (TCP & UDP)
- **IP Type Detection** (Local vs. Public)
- **Stop a Running Port** (Close Services)
- **Check Running Ports in Real-Time**
- **Visualize Results with Charts**
""")

# Function to perform TCP Scan
def tcp_scan(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            st.write(f"[+] TCP Port {port} is Open")
            open_ports.append(port)
        else:
            closed_ports.append(port)
        sock.close()
    except Exception as e:
        st.error(f"Error scanning TCP port {port}: {e}")

# Function to perform UDP Scan
def udp_scan(target, port,timeout=3,retries=3):
        try:
            # Create UDP packet
            udp_packet = scapy.IP(dst=target)/scapy.UDP(dport=port)
        
            # Send the packet and wait for a response (timeout increased to 30 seconds)
            response = scapy.sr1(udp_packet, timeout=30, verbose=0)
        
            if response is None:
                # No response might indicate open/filtered port
                st.write(f"[+] UDP Port {port} might be Open or Filtered")
                open_ports.append(port)  # Appending to the global list of open ports
            else:
                # Response indicates the port is closed
                st.write(f"[-] UDP Port {port} is Closed")
                closed_ports.append(port)  # Appending to the global list of closed ports
        
        except Exception as e:
            # Handle errors
            st.error(f"Error scanning UDP port {port}: {e}")

# Function to check running ports in real-time
def check_running_ports():
    running_ports = []
    for conn in psutil.net_connections():
        if conn.status == "LISTEN":
            running_ports.append(conn.laddr.port)
    return running_ports

# Function to initiate scanning
def port_scanner(target, start_port, end_port, scan_type):
    global open_ports, closed_ports
    open_ports = []
    closed_ports = []
    threads = []

    for port in range(start_port, end_port + 1):
        if scan_type == "TCP":
            thread = threading.Thread(target=tcp_scan, args=(target, port))
        elif scan_type == "UDP":
            thread = threading.Thread(target=udp_scan, args=(target, port))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    # Visualization
    visualize_results(open_ports, closed_ports) 

# Function to check if an IP is private or public
def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False  # In case of invalid IP

# Function to stop a port
def close_port(port):
    for conn in psutil.net_connections():
        if conn.laddr.port == port and conn.status == "LISTEN":
            pid = conn.pid
            st.warning(f"Closing port {port} (Process ID: {pid})")
            os.system(f"taskkill /PID {pid} /F" if os.name == "nt" else f"kill -9 {pid}")
            return
    st.error(f"No process found running on port {port}")

def is_connected_to_internet():
    try:
        socket.create_connection(("www.google.com", 80), timeout=10)
        return True
    except socket.error:
        return False



def subnet_scan(subnet):
    active_hosts = []
    ip_list = list(ipaddress.ip_network(subnet).hosts())  # Get all usable IPs

    with st.spinner(f"Scanning subnet {subnet}..."):
        for ip in ip_list:
            try:
                response = os.system(f"ping -c 1 -W 1 {ip}" if os.name != "nt" else f"ping -n 1 -w 1000 {ip}")
                if response == 0:
                    active_hosts.append(str(ip))
            except Exception as e:
                st.error(f"Error scanning {ip}: {e}")
    
    return active_hosts, ip_list

def scan_ports_on_active_hosts(active_hosts, start_port, end_port, scan_type):
    subnet_scan_results = {}

    for host in active_hosts:
        st.write(f"🔍 Scanning ports on {host}...")
        global open_ports, closed_ports
        open_ports = []
        closed_ports = []

        threads = []

        for port in range(start_port, end_port + 1):
            if scan_type == "TCP":
                thread = threading.Thread(target=tcp_scan, args=(host, port))
            elif scan_type == "UDP":
                thread = threading.Thread(target=udp_scan, args=(host, port))
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

        subnet_scan_results[host] = {
            "open_ports": open_ports.copy(),
            "closed_ports": closed_ports.copy()
        }

    return subnet_scan_results


st.markdown(" ### 📡 Subnet Scanner")

subnet_input = st.text_input("Enter Subnet to Scan (e.g., 192.168.1.0/24)", key="subnet_input")



# Streamlit UI with unique key for text_input to avoid conflict
target_ip = st.text_input("Enter Target IP:", key="target_ip_input")
if target_ip:
    try:
        # Try to parse the IP as IPv4
        ip = IPv4Address(target_ip)
        st.success(f"Valid IPv4 address: {target_ip}")
    except AddressValueError:
        try:
            # If IPv4 fails, try to parse as IPv6
            ip = IPv6Address(target_ip)
            st.success(f"Valid IPv6 address: {target_ip}")
        except AddressValueError:
            # If both IPv4 and IPv6 fail, it's invalid
            st.error("Invalid IP address format.")
            target_ip = None  # Prevent further execution

    if target_ip:  # Proceed only if valid IP
        # Check if the IP address is private or public
        if not is_private_ip(target_ip):
            # If it's a public IP and there's no internet, show a warning
            st.info(f"{target_ip} is a Public IP address.")
        else:
            st.info(f"{target_ip} is a Private IP address.")

        if not is_connected_to_internet():
            st.warning(f"{target_ip}  No internet connection is available. Scanning will be limited to the local network.")
    else:
        st.warning("Please enter a valid IP address.")

# Add option to choose between single port or port range
port_input_type = st.radio("Select Port Type:", ["Single Port", "Port Range"])

if port_input_type == "Single Port":
    port = st.number_input("Enter Port:", min_value=1, max_value=65535, value=8080)
    start_port = port
    end_port = port
elif port_input_type == "Port Range":
    start_port = st.number_input("Enter Start Port:", min_value=1, max_value=65535, value=1)
    end_port = st.number_input("Enter End Port:", min_value=1, max_value=65535, value=1024)

scan_type = st.radio("Select Scan Type:", ["TCP", "UDP"])

if st.button("Start Scan"):
    if target_ip:
        open_ports = []
        closed_ports = [] 
        with st.spinner('Scanning...'):
            port_scanner(target_ip, start_port, end_port, scan_type)
    else:
        st.error("Please enter a valid IP address before scanning.")

if st.button("Start Subnet Scan"):
    try:
        subnet = ipaddress.ip_network(subnet_input, strict=False)
        active_hosts, ip_list = subnet_scan(str(subnet))
        visualize_subnet_results(active_hosts, len(ip_list), ip_list)

        if active_hosts:
            st.markdown("### 🔐 Starting Port Scan on Active Hosts")
            port_scan_results = scan_ports_on_active_hosts(active_hosts, start_port, end_port, scan_type)

            # Display results
            for host, results in port_scan_results.items():
                st.subheader(f"Host: {host}")
                st.write(f"🟢 Open Ports: {results['open_ports']}")
                st.write(f"🔴 Closed Ports: {results['closed_ports']}")
                visualize_results(results['open_ports'], results['closed_ports'])

        else:
            st.warning("No active hosts found in the subnet.")

    except ValueError:
        st.error("Invalid subnet format. Please enter like 192.168.1.0/24")


if st.button("Check Running Ports in Real-Time"):
    if target_ip:
        running_ports = check_running_ports()
        st.write("Currently Running Ports:", running_ports)
    else:
        st.error("Please enter a valid IP address to check running ports.")

if st.button("Check if IP is Private or Public"):
    if target_ip:
        if is_private_ip(target_ip):
            st.success(f"{target_ip} is a Private (Local Network) IP.")
        else:
            st.warning(f"{target_ip} is a Public (Internet) IP.")
    else:
        st.error("Please enter a valid IP address to check.")

port_to_close = st.number_input("Enter Port to Close:", min_value=1, max_value=65535, value=8080)
if st.button("Close Port"):
    if target_ip:
        close_port(port_to_close)
    else:
        st.error("Please enter a valid IP address to close the port.")
