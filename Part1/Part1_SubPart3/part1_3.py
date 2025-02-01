import matplotlib.pyplot as plt
from scapy.all import rdpcap, sniff
from collections import defaultdict

dataTransferred = 0
packetSizes = []
totalPackets = 0
capture_duration = 60

def part1_subpart3(packets):
    # ASSUMPTIONS
    # what we have to show Data Flow or count no of flows through this port
    # In Find out which source-destination have transferred the most data. --> no of times or in size
    # also do we have to give pair that has most source-destination data transferred

    sourceTotalFlows = {}
    sourceDataFlows = {}
    destinationTotalFlows = {}
    destinationDataFlows = {}

    for pkt in packets:
        if pkt.haslayer('IP'):
            srcIP = pkt['IP'].src
            if srcIP not in sourceTotalFlows:
                sourceTotalFlows[srcIP] = 1
                sourceDataFlows[srcIP] = len(pkt)
            else:
                sourceTotalFlows[srcIP] += 1
                sourceDataFlows[srcIP] += len(pkt)

            dstIP = pkt['IP'].dst
            if dstIP not in destinationTotalFlows:
                destinationTotalFlows[dstIP] = 1
                destinationDataFlows[dstIP] = len(pkt)
            else:
                destinationTotalFlows[dstIP] += 1
                destinationDataFlows[dstIP] += len(pkt)

    # ----------------------- No of times -----------------------
    print("Total Source Flows:")
    maxSrcIP = 0
    maxFlowCount = 0
    for srcIP, flowCount in sourceTotalFlows.items():
        print(f"{srcIP}: {flowCount}")
        if(flowCount > maxFlowCount):
            maxSrcIP = srcIP
            maxFlowCount = flowCount

    print("Destination Source Flows:")
    maxDstIP = 0
    maxFlowCount = 0
    for dstIP, flowCount in destinationTotalFlows.items():
        print(f"{dstIP}: {flowCount}")
        if(flowCount > maxFlowCount):
            maxDstIP = dstIP
            maxFlowCount = flowCount

    # -------------------------- Data ---------------------------
    # print("Total Data Flows:")
    maxSrcIP = 0
    maxFlowData = 0
    for srcIP, flowData in sourceDataFlows.items():
        # print(f"{srcIP}: {flowData}")
        if(flowData > maxFlowData):
            maxSrcIP = srcIP
            maxFlowData = flowData

    # print("Destination Data Flows:")
    maxDstIP = 0
    maxFlowData = 0
    for dstIP, flowData in destinationDataFlows.items():
        # print(f"{dstIP}: {flowData}")
        if(flowData > maxFlowData):
            maxDstIP = dstIP
            maxFlowData = flowData

    print(f'Source IP with most data flows is {maxSrcIP} with {maxFlowCount} flows.')
    print(f'Destination IP with most data flows is {maxDstIP} with {maxFlowCount} flows.')

    dataTransfer = {}

    for pkt in packets:
        if pkt.haslayer('IP') and (pkt.haslayer('TCP') or pkt.haslayer('UDP')):
            srcIP = pkt['IP'].src
            dstIP = pkt['IP'].dst

            if(pkt.haslayer('TCP')):
                srcPort = pkt['TCP'].sport
                dstPort = pkt['TCP'].dport
                pair = (srcIP, srcPort, dstIP, dstPort)

            elif pkt.haslayer('UDP'):
                srcPort = pkt['UDP'].sport
                dstPort = pkt['UDP'].dport
                pair = (srcIP, srcPort, dstIP, dstPort)

            dataSize = len(pkt)  # pkt.payload

            if pair not in dataTransfer:
                dataTransfer[pair] = dataSize
            else:
                dataTransfer[pair] += dataSize

    # maxPair = 0
    maxData = 0
    for pair, flowData in dataTransfer.items():
        # print(f"{Pair}: {flowData}")
        if(flowData > maxData):
            # maxPair = pair
            maxData = flowData

    for pair, flowData in dataTransfer.items():
        if(flowData == maxData):
            print(f'source-destination (source IP:port and destination IP:port) that have transferred the most data is {pair} with {maxData} data (in bytes).')


def live_capture_part1_subpart3(interface="enp0s3"):
    print(f"Starting live capture on interface {interface}...")
    packets = sniff(iface=interface, timeout=capture_duration)
    part1_subpart3(packets)

if __name__ == "__main__":
    live_capture_part1_subpart3()