import pyshark

def print_all_packets(pcap_file_path):
    capture = pyshark.FileCapture(pcap_file_path)
    for packet in capture:
        print(packet)

if __name__ == "__main__":
    pcap_file_path = "ieee802154_on.pcap"
    print_all_packets(pcap_file_path)
    
    
    """
    
    import logging
logging.basicConfig(level=logging.DEBUG)
import pyshark
import sys


def delve_into_zigbee_communication(pcap_file_path):
    capture = pyshark.FileCapture(pcap_file_path, display_filter="wpan")
    zigbee_packets = []

    for packet in capture:
        if hasattr(packet, "wpan") and hasattr(packet.wpan, "zigbee"):
            zigbee_packets.append(packet)
            logging.debug(f"Captured Zigbee packet: {packet}")

    capture.close()
    return zigbee_packets

def find_network_key(pcap_file_path):
    capture = pyshark.FileCapture(pcap_file_path)

    for packet in capture:
        if hasattr(packet, 'wpan') and hasattr(packet.wpan, 'zigbee') and hasattr(packet.wpan.zigbee, 'nwk_key_descriptor'):
            return packet.wpan.zigbee.nwk_key_descriptor.network_key

    return None

def find_transport_key(pcap_file_path):
    capture = pyshark.FileCapture(pcap_file_path)

    for packet in capture:
        if hasattr(packet, 'wpan') and hasattr(packet.wpan, 'zigbee') and hasattr(packet.wpan.zigbee, 'sec') and hasattr(packet.wpan.zigbee.sec, 'nwk_fc'):
            if int(packet.wpan.zigbee.sec.nwk_fc, 16) & 0b10:
                return packet.wpan.zigbee.sec.security_key

    return None


def count_zigbee_packets(pcap_file_path):
    capture = pyshark.FileCapture(pcap_file_path)
    zigbee_count = 0

    for packet in capture:
        if hasattr(packet, 'wpan') and hasattr(packet.wpan, 'zigbee'):
            zigbee_count += 1

    return zigbee_count


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 key.py <path_to_pcap_file>")
        sys.exit(1)

    pcap_file_path = sys.argv[1]
    delve_into_zigbee_communication(pcap_file_path)
    network_key = find_network_key(pcap_file_path)
    transport_key = find_transport_key(pcap_file_path)
    total_zigbee_packets = count_zigbee_packets(pcap_file_path)

    print(f"Network Key: {network_key}")
    print(f"Transport Key: {transport_key}")
    print(f"Total Zigbee packets in the capture: {total_zigbee_packets}")


    
    """
