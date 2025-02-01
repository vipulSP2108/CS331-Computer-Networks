import matplotlib.pyplot as plt
from scapy.all import rdpcap, sniff
from collections import defaultdict

dataTransferred = 0
packetSizes = []
totalPackets = 0
capture_duration = 60

def part1_subpart1(packets):
    dataTransferred = 0
    packetSizes = []

    for pkt in packets:
        # Difference between pkt.payload and pkt (entire packet size)
        dataTransferred += len(pkt)
        packetSizes.append(len(pkt))

    totalPackets = len(packets)
    avgSize = dataTransferred / totalPackets if totalPackets > 0 else 0

    print(f'Total amount of data transferred: {dataTransferred} bytes')
    print(f"Total number of packets transferred: {totalPackets}")
    print(f'Minimum packet size: {min(packetSizes)} bytes')
    print(f'Maximum packet size: {max(packetSizes)} bytes')
    print(f'Average packet size: {avgSize:.2f} bytes')

    print("Distribution of packet sizes (histogram of packet sizes)")
    plt.hist(packetSizes, bins=50, edgecolor='black')
    plt.xlabel('Packet size (bytes)')
    plt.ylabel('Frequency')
    plt.title('Distribution of packet sizes (histogram of packet sizes)')
    plt.show()

def live_capture_part1_subpart1(interface="enp0s3"):
    print(f"Starting live capture on interface {interface}...")
    packets = sniff(iface=interface, timeout=capture_duration)
    part1_subpart1(packets)

if __name__ == "__main__":
    live_capture_part1_subpart1()