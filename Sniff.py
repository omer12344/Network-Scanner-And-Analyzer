from filters import filter_tcp_udp
from scapy.all import *
from scapy.layers.inet import TCP, IP, ICMP, UDP, Ether
from scapy.layers.l2 import ARP
from scapy.layers.dhcp import DHCP
from scapy.layers.http import HTTP
from scapy.layers.dns import DNS
import netifaces as ni
from IP import Ip
from send_email import send_email_report
from ScanLan import ScanLanSession


class SniffSession:

    def __init__(self, how_many_packets: int, list_of_open_ipsobj: List[Ip], list_of_open_ips: List[str],
                 email_receiver):
        self.packets = sniff(filter="ip", count=how_many_packets, lfilter=filter_tcp_udp)
        self.protocols_stats = {
            "Application": {"DNS": 0, "HTTP": 0},
            "Transport": {"TCP": 0, "UDP": 0},
            "Network": {"DHCP": 0, "ICMP": 0},
            "Link layer": {"ARP": 0, "Ethernet": 0}
        }
        self.how_many_packets = how_many_packets
        self.list_of_open_ips = list_of_open_ips
        self.list_of_open_ipsobj = list_of_open_ipsobj
        self.email_security_report_body = ""
        self.sniff_summary = "SUMMERY-----------SUMMERY-----------SUMMERY-----------" \
                             "SUMMERY------------SUMMERY------------------SUMMERY----\n"
        self.email_sender = 'aonetworkscanner@gmail.com'
        self.email_sender_password = 'otgf zwou mxwm bxuy'
        self.email_receiver = email_receiver
        self.subnet_part = self.get_subnet_part()
        self.sniff_packets()

    @staticmethod
    def get_subnet_part():
        for interface in ni.interfaces():
            addresses = ni.ifaddresses(interface)
            if ni.AF_INET in addresses:
                for link in addresses[ni.AF_INET]:
                    ip_address = link['addr']
                    subnet_mask = link['netmask']

                    # Ignore localhost
                    if ip_address != "127.0.0.1":
                        # Convert IP address and subnet mask to integers
                        ip_int = struct.unpack('!I', socket.inet_aton(ip_address))[0]
                        subnet_mask_int = struct.unpack('!I', socket.inet_aton(subnet_mask))[0]

                        # Calculate the network address
                        network_address_int = ip_int & subnet_mask_int

                        # Convert the network address back to dotted decimal format
                        network_address = socket.inet_ntoa(struct.pack('!I', network_address_int))

                        # Extract the first two octets for the subnet part
                        return str('.'.join(network_address.split('.')[:2]) + '.')

        return "No valid interface found."

    def is_threat(self, entity, packet_count):
        if packet_count >= (self.how_many_packets / 2):
            self.email_security_report_body += f'this global ip {entity} might be a volumetric dos threat \n'

    def append_to_sniff_summary(self, message):
        """
        Append a message to the summary.
        """
        self.sniff_summary += message + '\n'

    def inspect_packets_local_net(self, local_net_packets):
        """
        Inspect the packets sent and received on the local network and count the number of packets for each IP address.
        """
        for ip in self.list_of_open_ipsobj:
            ports_for_sending = {str(port): 0 for port in
                                 range(20, 1024)}  # fills dictionary of ports for receiving for each ip
            ports_for_receiving = {str(port): 0 for port in
                                   ip.get_port_list()}  # fills dictionary of ports for sending for each ip

            packet_stats = {
                'from_src': 0,
                'to_src': 0,
                'dhcp_sent': 0,
                'trs_sent': 0,
                'dhcp_received': 0,
                'trs_received': 0,
            }

            for packet in local_net_packets:
                if str(packet[IP].src) == str(ip.get_ip()):
                    packet_stats['from_src'] += 1
                    try:
                        protocol = TCP if TCP in packet else UDP
                        ports_for_sending[packet[protocol].sport] += 1
                        packet_stats['trs_sent'] += 1
                    except KeyError:
                        packet_stats['dhcp_sent'] += 1
                elif str(packet[IP].dst) == str(ip.get_ip()):
                    packet_stats['to_src'] += 1
                    try:
                        protocol = TCP if TCP in packet else UDP
                        ports_for_receiving[packet[protocol].dport] += 1
                        packet_stats['trs_received'] += 1
                    except KeyError:
                        packet_stats['dhcp_received'] += 1

            self.ip_report(ip, ports_for_sending, ports_for_receiving, packet_stats)

    def ip_report(self, ip, ports_for_sending, ports_for_receiving, packet_stats):
        print(f"On the local network, IP {ip.get_ip()} sent: {packet_stats['from_src']} packets")
        self.append_to_sniff_summary(f"On the local network, IP {ip.get_ip()} sent: {packet_stats['from_src']} packets")
        print(f"The local IP {ip.get_ip()} sent this many DHCP packets: {packet_stats['dhcp_sent']}")
        self.append_to_sniff_summary(
            f"The local IP {ip.get_ip()} sent this many DHCP packets: {packet_stats['dhcp_sent']}")
        print(f"The local IP {ip.get_ip()} sent this many transport layer packets: {packet_stats['trs_sent']}")
        self.append_to_sniff_summary(
            f"The local IP {ip.get_ip()} sent this many transport layer packets: {packet_stats['trs_sent']}")
        print(f"This local IP {ip.get_ip()} sent transport layer packets using these ports:\n")
        self.append_to_sniff_summary(f"This local IP {ip.get_ip()} sent transport layer packets using these ports:\n")
        for key, value in ports_for_sending.items():
            if value != 0:
                print(f"This port {key} sent this many packets: {value}")
                self.append_to_sniff_summary(f"This port {key} sent this many packets: {value}")
        print(f"On the local network, IP {ip.get_ip()} received: {packet_stats['to_src']} packets")
        self.append_to_sniff_summary(
            f"On the local network, IP {ip.get_ip()} received: {packet_stats['to_src']} packets")
        print(f"The local IP {ip.get_ip()} received this many DHCP packets: {packet_stats['dhcp_received']}")
        self.append_to_sniff_summary(
            f"The local IP {ip.get_ip()} received this many DHCP packets: {packet_stats['dhcp_received']}")
        print(f"The local IP {ip.get_ip()} received this many transport layer packets: {packet_stats['trs_received']}")
        self.append_to_sniff_summary(
            f"The local IP {ip.get_ip()} received this many transport layer packets: {packet_stats['trs_received']}")
        print(f"This local IP {ip.get_ip()} received transport layer packets using these ports:\n")
        self.append_to_sniff_summary(
            f"This local IP {ip.get_ip()} received transport layer packets using these ports:\n")
        for key, value in ports_for_receiving.items():
            if value != 0:
                print(f"This port {key} received this many packets: {value}")
                self.append_to_sniff_summary(f"This port {key} received this many packets: {value}")

    def inspect_packets_global_net(self, list_of_outer_packets):
        """
        Inspect the packets sent from or received by global IPs and count the number of packets for each IP address.
        """
        outer_ips_sent = {}
        outer_ips_recieved = {}
        for p in list_of_outer_packets:
            if str(p[IP].src) not in outer_ips_sent.keys() and self.subnet_part not in str(p[IP].src):
                outer_ips_sent[p[IP].src] = 0
            elif str(p[IP].dst) not in outer_ips_recieved.keys() and self.subnet_part not in str(p[IP].dst):
                outer_ips_recieved[str(p[IP].dst)] = 0

        for p in list_of_outer_packets:  # dict[outer_ip]=num_of_packets
            if p[IP].src in outer_ips_sent.keys():
                outer_ips_sent[p[IP].src] += 1
            elif p[IP].dst in outer_ips_recieved.keys():
                outer_ips_recieved[p[IP].dst] += 1

        print("These are the global IPs that communicated with our local network:")
        self.append_to_sniff_summary("These are the global IPs that communicated with our local network:")

        seen = {}
        for ip in outer_ips_sent.keys():
            seen[ip] = 0
            print(str(ip))
            self.append_to_sniff_summary(str(ip))
        for ip in outer_ips_recieved:
            if ip not in seen.keys():
                print(str(ip))
                self.append_to_sniff_summary(str(ip))

        for global_ip in outer_ips_sent.keys():
            print("----------------------------------------------------------------------")
            self.append_to_sniff_summary("----------------------------------------------------------------------")
            print("From global IP address: " + str(
                global_ip) + ", the number of packets sent to our local network were: " + str(
                outer_ips_sent[global_ip]))
            self.append_to_sniff_summary("From global IP address: " + str(
                global_ip) + ", the number of packets sent to our local network were: " + str(
                outer_ips_sent[global_ip]))
            self.is_threat(global_ip, outer_ips_sent[global_ip])
            self.create_global_local_dictionary(global_ip, list_of_outer_packets)

    def create_global_local_dictionary(self, outer_ip, list_of_outer_packets):
        """
        Create a dictionary with local IPs as keys and the number of packets sent from
        the outer IP to each local IP as values.
        """
        final_dict = {}
        for ip in self.list_of_open_ips:
            final_dict[str(ip.get_ip())] = 0
        if ScanLanSession.get_local_ip() not in final_dict:
            final_dict[str(ScanLanSession.get_local_ip())] = 0
        for packet in list_of_outer_packets:
            if packet[IP].src == outer_ip:
                final_dict[str(packet[IP].dst)] += 1
        print("Detailed explanation about the sent packets from " + outer_ip + ":\n")
        self.append_to_sniff_summary("Detailed explanation about the exchanged packets from " + outer_ip + ":\n")
        for key in final_dict:
            print(str(final_dict[key]) + " packets were sent to this local IP address: " + key + "\n")
            self.append_to_sniff_summary(
                str(final_dict[key]) + " packets were sent to this local IP address: " + key + "\n")
            self.create_port_dictionary(list_of_outer_packets, key, outer_ip)

    def create_port_dictionary(self, list_of_outer_packets, local_ip, outer_ip):
        """
        Create dictionaries with ports as keys and the number of packets sent/received through each port as values.
        """
        global_port = {str(port): 0 for port in range(0, 65600)}
        local_port = {str(port): 0 for port in range(1024, 65600)}
        for Ip in self.list_of_open_ipsobj:
            if Ip.get_ip() == local_ip:
                for port in Ip.get_port_list():
                    local_port[port] = 0
        count_bad_packets = 0
        for packet in list_of_outer_packets:
            if packet[IP].src == str(outer_ip) and packet[IP].dst == str(local_ip):
                try:
                    try:
                        global_port[str(packet[TCP].sport)] += 1
                        local_port[str(packet[TCP].dport)] += 1
                    except:
                        global_port[str(packet[UDP].sport)] += 1
                        local_port[str(packet[UDP].dport)] += 1
                except Exception as unexpected:
                    self.append_to_sniff_summary(str(unexpected))
                    count_bad_packets += 1
        print("From this global IP " + str(outer_ip) + " to this local IP " + local_ip + ":\n")
        self.append_to_sniff_summary("From this global IP " + str(outer_ip) + " to this local IP " + local_ip + ":\n")
        if count_bad_packets != 0:
            print(str(count_bad_packets) + " packets were below the transport layer")
            self.append_to_sniff_summary(str(count_bad_packets) + " packets were below the transport layer")
        count = 0
        for key in global_port:
            if global_port[key] != 0:
                print("Global IP " + str(outer_ip) + " used this port " + str(key) +
                      " for sending this many packets: " + str(global_port[key]))
                self.append_to_sniff_summary("Global IP " + str(outer_ip) + " used this port " + str(key) +
                                             " for sending this many packets: " + str(global_port[key]))
                count += 1
        for key in local_port:
            if local_port[key] != 0:
                print("Local IP " + str(local_ip) + " used this port " + str(key) +
                      " for receiving this many packets: " + str(local_port[key]))
                self.append_to_sniff_summary("Local IP " + str(local_ip) + " used this port " + str(key) +
                                             "for receiving this many packets: " + str(local_port[key]))
                count += 1
        if count == 0:
            print("0 ports were in use because all packets exchanged were below the transport layer,"
                  " or 0 packets were exchanged between them.")
            self.append_to_sniff_summary("0 ports were in use because all packets exchanged were below"
                                         " the transport layer, or 0 packets were exchanged between them.")
        print("----------------------------------------------------------------------")
        self.append_to_sniff_summary("----------------------------------------------------------------------")

    def sniff_packets(self):
        packets = self.packets
        print("sniffed all packets")
        self.append_to_sniff_summary("sniffed all packets")
        local_net_packets = []
        global_net_packets = []
        broadcast_flag = False
        for packet in packets:
            if packet[IP].dst == '255.255.255.255' or packet[IP].src == '255.255.255.255':
                broadcast_flag = True
                local_net_packets.append(packet)
            if packet[IP].dst == '0.0.0.0' or packet[IP].src == '0.0.0.0':
                broadcast_flag = True
                local_net_packets.append(packet)
            if broadcast_flag is False:
                flag = False
                for ip in self.list_of_open_ipsobj:
                    if self.subnet_part in packet[IP].src and self.subnet_part in packet[IP].dst:
                        flag = True
                        break
                if flag:
                    local_net_packets.append(packet)
                else:
                    global_net_packets.append(packet)  # packets we got and recieved from global and to global
        for packet in packets:
            if HTTP in packet:
                self.protocols_stats["Application"]["HTTP"] += 1
            elif DNS in packet:
                self.protocols_stats["Application"]["DNS"] += 1
            elif TCP in packet:
                self.protocols_stats["Transport"]["TCP"] += 1
            elif UDP in packet:
                self.protocols_stats["Transport"][
                    "UDP"] += 1  # add another for loop with all protocols, instead of a lot of "if"
            elif DHCP in packet:
                self.protocols_stats["Network"]["DHCP"] += 1
            elif ICMP in packet:
                self.protocols_stats["Network"]["ICMP"] += 1
            elif ARP in packet:
                self.protocols_stats["Link layer"]["ARP"] += 1
            elif Ether in packet:
                self.protocols_stats["Link layer"]["Ethernet"] += 1
        for key in self.protocols_stats:
            print("From layer: " + str(key))
            self.append_to_sniff_summary("From layer: " + str(key))
            for key2 in self.protocols_stats[key]:
                print("From protocol " + str(key2) + ", the number of packets: " + str(self.protocols_stats[key][key2]))
                self.append_to_sniff_summary(
                    "From protocol " + str(key2) + ", the number of packets: " + str(self.protocols_stats[key][key2]))
        print()
        self.append_to_sniff_summary('\n')
        self.inspect_packets_local_net(local_net_packets)
        self.inspect_packets_global_net(global_net_packets)
        send_email_report(self.email_receiver, self.email_security_report_body, 'Security Threats Report')
        send_email_report(self.email_receiver, self.sniff_summary, 'Traffic Report')

