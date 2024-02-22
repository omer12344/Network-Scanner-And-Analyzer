from scapy.packet import Packet
from scapy.layers.inet import IP, TCP, UDP

def filter_tcp_udp(packet: Packet) -> bool:
    """
    Filter TCP and UDP packets.
    :param packet: The packet to be checked.
    :return: True if the packet is TCP or UDP, False otherwise.
    """
    return IP in packet and (TCP in packet or UDP in packet)
