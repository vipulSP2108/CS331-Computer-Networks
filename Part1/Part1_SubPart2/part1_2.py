import matplotlib.pyplot as plt
from scapy.all import rdpcap, sniff
from collections import defaultdict

dataTransferred = 0
packetSizes = []
totalPackets = 0
capture_duration = 60

def part1_subpart2(packets):
    uniquePairsTCP = set()
    uniquePairsUDP = set()

    for pkt in packets:
        if pkt.haslayer('IP') and (pkt.haslayer('TCP') or pkt.haslayer('UDP')):
            srcIP = pkt['IP'].src
            dstIP = pkt['IP'].dst

            if(pkt.haslayer('TCP')):
                srcPort = pkt['TCP'].sport
                dstPort = pkt['TCP'].dport
                pair = (srcIP, srcPort, dstIP, dstPort)
                if pair not in uniquePairsTCP:
                    uniquePairsTCP.add(pair)

            # Que: Do we need to consider UDP in unique port calculation? I think Yes.
            ##### if no => Unique pairs --> 41077 -place pe- 32493

            if(pkt.haslayer('UDP')):
                srcPort = pkt['UDP'].sport
                dstPort = pkt['UDP'].dport
                pair = (srcIP, srcPort, dstIP, dstPort)
            if pair not in uniquePairsUDP:
                uniquePairsUDP.add(pair)

    print('unique source-destination pairs with TCP port')
    for pair in uniquePairsTCP:
      print(pair)

    print('unique source-destination pairs with UDP port')
    for pair in uniquePairsUDP:
      print(pair)

    print(f'Total number of unique source-destination pairs in the captured data are {len(uniquePairsTCP) + len(uniquePairsUDP)}')
    print(f'out of which {len(uniquePairsTCP)} are TCP connections and {len(uniquePairsUDP)} are UDP connections')

def live_capture_part1_subpart2(interface="enp0s3"):
    print(f"Starting live capture on interface {interface}...")
    packets = sniff(iface=interface, timeout=capture_duration)
    part1_subpart2(packets)

if __name__ == "__main__":
    live_capture_part1_subpart2()