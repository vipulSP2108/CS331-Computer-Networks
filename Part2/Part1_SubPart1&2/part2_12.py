import matplotlib.pyplot as plt
from scapy.all import rdpcap, sniff
from collections import defaultdict

dataTransferred = 0
packetSizes = []
totalPackets = 0
capture_duration = 60

def part2_subpart1and2(packets):
    for pkt in packets:
        if pkt.haslayer('Raw'):
            payload = str(pkt['Raw'].load)
            if 'subject' in payload.lower():
                start_index = payload.lower().find('subject')
                end_index = start_index + len('subject')
                # print(payload)

                start_slice = max(0, start_index - 70)
                end_slice = min(len(payload), end_index + 130)
                print(payload[start_slice:end_slice])
                print('')

def live_capture_part2_subpart1and2(interface="enp0s3"):
    print(f"Starting live capture on interface {interface}...")
    packets = sniff(iface=interface, timeout=capture_duration)
    part2_subpart1and2(packets)

if __name__ == "__main__":
    live_capture_part2_subpart1and2()