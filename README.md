# CS331 - Computer Networks: Network Traffic Capture & Replay

## Overview
This project demonstrates the process of capturing network traffic from a specific interface and then replaying the captured traffic. We explore two methods for capturing traffic and replaying it: using `tcpreplay` and `tcpdump` for the first method, and using Python for the second.

## Requirements
- Linux OS (Debian-based or similar)
- `tcpreplay` and `tcpdump` installed
- `sudo` privileges
- Python 3.x (if using the Python-based approach)
- Network interface: `enp0s3` (or modify the interface name accordingly)

---

## Method 1: Using `tcpreplay` and `tcpdump` (in 10_22110189_22110289.ipynb)

In this method, we capture Network Traffic using:

to get info about the details of interface use

```bash
ifconfig
```

```bash
sudo tcpreplay --topspeed stats=60 -i enp0s3 /home/student/Downloads/1.pcap
```

## Method 2: Using `tcpreplay` with Python Script (in Folders)

In this method, the network traffic is replayed using a Python script along with tcpreplay.

```bash
sudo tcpreplay -i enp0s3 /home/student/Downloads/1.pcap
```

```bash
cd /home/student/Downloads
sudo python3 file-name.py
```

## To get full overview check the 10_22110189_22110289.pdf

