import pyshark
import sys


def delve_into_zigbee_communication(pcap_file_path):
    capture = pyshark.FileCapture(pcap_file_path, display_filter="wpan")
    zigbee_packets = []

    for packet in capture:
        if hasattr(packet, "wpan") and hasattr(packet.wpan, "zigbee"):
            zigbee_packets.append(packet)

    capture.close()
    return zigbee_packets


def find_network_key(zigbee_packets):
    network_key = None

    for packet in zigbee_packets:
        if hasattr(packet, "wpan") and hasattr(packet.wpan, "zigbee") and hasattr(packet.wpan.zigbee, "nwk_key_descriptor"):
            network_key = packet.wpan.zigbee.nwk_key_descriptor.network_key

    return network_key


def find_transport_key(zigbee_packets):
    transport_key = None

    for packet in zigbee_packets:
        if hasattr(packet, "wpan") and hasattr(packet.wpan, "zigbee") and hasattr(packet.wpan.zigbee, "sec") and hasattr(packet.wpan.zigbee.sec, "nwk_fc"):
            if int(packet.wpan.zigbee.sec.nwk_fc, 16) & 0b10:
                transport_key = packet.wpan.zigbee.sec.security_key

    return transport_key


def count_zigbee_packets(zigbee_packets):
    zigbee_count = 0

    for packet in zigbee_packets:
        zigbee_count += 1

    return zigbee_count


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 key.py <path_to_pcap_file>")
        sys.exit(1)

    pcap_file_path = sys.argv[1]
    zigbee_packets = delve_into_zigbee_communication(pcap_file_path)
    network_key = find_network_key(zigbee_packets)
    transport_key = find_transport_key(zigbee_packets)
    total_zigbee_packets = count_zigbee_packets(zigbee_packets)

    print(f"Network Key: {network_key}")
    print(f"Transport Key: {transport_key}")
    print(f"Total Zigbee packets in the capture: {total_zigbee_packets}")


if __name__ == "__main__":
    main()

