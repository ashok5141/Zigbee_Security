import pyshark

def find_network_key(packet):
    if 'wpan' in packet and 'zbee_nwk' in packet.wpan and 'key' in packet.wpan.zbee_nwk:
        return packet.wpan.zbee_nwk.key

def find_transport_key(packet):
    if 'wpan' in packet and 'zbee_sec' in packet.wpan and 'key' in packet.wpan.zbee_sec:
        return packet.wpan.zbee_sec.key

def count_zigbee_packets(pcap_file_path):
    count = 0
    capture = pyshark.FileCapture(pcap_file_path, display_filter='wpan')
    for _ in capture:
        count += 1
    return count

if __name__ == "__main__":
    pcap_file_path = "ieee802154_on.pcap"
    network_key = None
    transport_key = None
    total_zigbee_packets = 0

    try:
        total_zigbee_packets = count_zigbee_packets(pcap_file_path)
        capture = pyshark.FileCapture(pcap_file_path, display_filter='wpan')
        for packet in capture:
            if network_key is None:
                network_key = find_network_key(packet)
            if transport_key is None:
                transport_key = find_transport_key(packet)
            if network_key and transport_key:
                break

    except Exception as e:
        print("Error:", e)

    print("Network Key:", network_key)
    print("Transport Key:", transport_key)
    print("Total Zigbee packets in the capture:", total_zigbee_packets)





