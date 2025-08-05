# 🚀 Real-Time Port Scanner & Controller

## 📌 Project Overview
This project is a **real-time network security tool** built using **Python and Streamlit**. It allows users to scan, monitor, and manage network ports efficiently. By leveraging **Scapy, socket, and psutil**, this tool helps identify open ports, running services, and potential vulnerabilities in a network.

## 🔥 Features
✅ **Real-time Port Scanning** (TCP & UDP)  
✅ **IP Type Detection** (Local vs. Public)  
✅ **Start a Port Listener** (Open Ports)  
✅ **Stop a Running Port** (Close Services)  
✅ **Check Running Ports in Real-Time**  
✅ **Visualize Results with Charts**  

## 🛠 Technologies Used
- **Python** - Core language for development.
- **Streamlit** - Web-based UI for real-time interaction.
- **Scapy** - Packet crafting and network analysis.
- **Socket Library** - For handling TCP/UDP connections.
- **Psutil** - To fetch real-time network statistics.
- **Matplotlib** - For data visualization.

## ⚡ How to Run the Project
1. **Install Dependencies**  
```bash
pip install streamlit scapy matplotlib psutil
```

2. **Run the Streamlit App**  
```bash
streamlit run script.py
```

3. **Interact via the Web UI**

## 📝 User Input Guide
| Input Type            | Example Value           | Description |
|----------------------|------------------------|-------------|
| **Target IP**        | `192.168.1.1` or `8.8.8.8` | IP address to scan |
| **Start Port**       | `1`                     | Beginning of the port range |
| **End Port**         | `1024`                   | End of the port range |
| **Scan Type**        | `TCP` or `UDP`          | Select scan protocol |
| **Open Port**        | `8080`                   | Start a listener on this port |
| **Close Port**       | `80`                     | Stop a running service |

## 🔄 Existing vs. Proposed Features
| **Existing Features**            | **Proposed Enhancements** |
|---------------------------------|---------------------------|
| Basic TCP scanning              | Real-time running port detection |
| Basic UDP scanning              | Ability to open & close ports |
| Manual input for scanning       | Automated visualization of results |
| No graphical UI                 | Interactive Streamlit dashboard |

## 🎯 Use Cases
- **Cybersecurity Audits** - Identify open ports and vulnerabilities.
- **Network Monitoring** - Detect active services in real time.
- **Ethical Hacking** - Penetration testing for organizations.
- **System Administration** - Manage and secure network resources.

## 📢 Conclusion
This project provides a **comprehensive** and **real-time** port scanning and management tool for **cybersecurity professionals, ethical hackers, and network administrators**. It enhances security assessments and network visibility with an easy-to-use **Streamlit UI**.

🚀 **Start scanning and securing your network today!**


🔢 Common CIDR Subnet Ranges

CIDR	Subnet Mask	      IPs in Subnet   	        Usable Host IPs	          Example Range
/8	   255.0.0.0	          16,777,216	              16,777,214	      10.0.0.0 – 10.255.255.255
/16	   255.255.0.0	          65,536	                  65,534	          192.168.0.0 – 192.168.255.255
/24	   255.255.255.0	      256	                      254	              192.168.1.0 – 192.168.1.255
/25	   255.255.255.128	      128	                      126	              192.168.1.0 – 192.168.1.127
/26	   255.255.255.192	      64                     	  62	              192.168.1.0 – 192.168.1.63
/27	   255.255.255.22     	  32	                      30	              192.168.1.0 – 192.168.1.31
/28	   255.255.255.240	      16	                      14	              192.168.1.0 – 192.168.1.15
/29	   255.255.255.248	      8	                          6	                  192.168.1.0 – 192.168.1.7
/30	   255.255.255.252	      4	                          2	                  192.168.1.0 – 192.168.1.3
/32	   255.255.255.255	      1	                          0 (Single Host)	  192.168.1.1
🧠 Usable Host IPs means subtracting network and broadcast addresses from total IPs.

🧪 Most Common for Scanning:
   Use Case	        CIDR	                   Why?
Home/Local Network	/24	    Covers 254 devices, common LAN

Tiny Networks/Test	/30	    Just 2 usable hosts

Private VPN/DMZ	    /16	         Covers 65k hosts
