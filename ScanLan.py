from scapy.all import *
from scapy.layers.inet import TCP, IP, ICMP
from IP import Ip
import socket
import struct
import netifaces as ni
from send_email import send_email_report
from IP import IpFactory
from threading import Thread
from time import sleep


class ScanLanSession:

    def __init__(self, email_receiver):
        self.lan_scan_summary = ""
        self.local_ips_objects: list[Ip] = []
        self.local_ips: list[str] = []
        self.Icount = 0
        self.local_ip = self.get_local_ip()
        self.iterate_hosts()
        self.local_ips = [Ip(str(ip), []) for ip in self.local_ips]
        self.check_ports_for_ip()
        self.add_services()
        send_email_report(email_receiver, self.lan_scan_summary, 'Lan Scanning Report')

    def append_to_summary(self, message):
        """
        Append a message to the summary.
        """
        self.lan_scan_summary += message + '\n'

    def get_subnet_info(self,):
        # Go through all network interfaces on our system
        for interface in ni.interfaces():
            # Get all addresses that are within this interface
            addresses = ni.ifaddresses(interface)
            # Check if the interface has an IPv4 address.
            if ni.AF_INET in addresses:
                self.Icount += 1
            # If the first interface with an IPv4 address is found, move forward with it.
            if ni.AF_INET in addresses and self.Icount == 1:
                for link in addresses[ni.AF_INET]:
                    # extract the ipv4 address and subnet of the interface
                    ip_address = link['addr']
                    subnet_mask = link['netmask']
                    # make sure it is not a loopback address
                    if ip_address != "127.0.0.1":
                        # calculate the number of bits of the subnet (the /x) ((CIDR notation)
                        subnet_prefix_length = sum([bin(int(x)).count('1') for x in subnet_mask.split('.')])
                        return ip_address, subnet_mask, subnet_prefix_length
        raise ValueError("No suitable network interface found.")

    @staticmethod
    def ip_range(ip_address, subnet_mask):
        if not ip_address or not subnet_mask:
            raise ValueError("IP address or subnet mask is missing.")
        # Convert the IP address and subnet mask from string to 32-bit integers
        ip_int = struct.unpack('!I', socket.inet_aton(ip_address))[0]
        subnet_mask_int = struct.unpack('!I', socket.inet_aton(subnet_mask))[0]

        #  performs a AND bitwise operation to calculate the network address
        network_address_int = ip_int & subnet_mask_int
        # Calculate the broadcast address with bitwise operations.
        broadcast_address_int = network_address_int | (~subnet_mask_int & 0xffffffff)

        start_address_int = network_address_int + 1
        end_address_int = broadcast_address_int - 1

        return start_address_int, end_address_int

    def iterate_hosts(self):
        try:
            ip_address, subnet_mask, subnet_prefix_length = self.get_subnet_info()
            start_address_int, end_address_int = self.ip_range(ip_address, subnet_mask)
            possible_hosts = []
            for host_int in range(start_address_int, end_address_int + 1):
                # Convert ip integer value back to string IP address
                host_ip = socket.inet_ntoa(struct.pack('!I', host_int))
                possible_hosts.append(host_ip)
            threads = []
            for host in possible_hosts:
                t = Thread(target=self.ping, args=(host,))
                t.start()
                threads.append(t)
            if self.local_ip not in self.local_ips:
                t = Thread(target=self.ping, args=(self.local_ip,))
                threads.append(t)
                t.start()
            count = 0
            for t in threads:
                t.join()
                count += 1
                if count == 30:
                    sleep(2)

        except ValueError as e:
            print(f"Error: {e}")

    def ping(self, host):
        """Ping the specified host to check if it is reachable."""
        #  change to ARP ping
        if self.local_ip == host:
            self.put_in_list(host, True)
            return
        ping_packet = IP(dst=str(host)) / ICMP()
        response = sr1(ping_packet, timeout=1, verbose=0)

        if response is None:
            print(f"IP {host} is not open.\n")
        elif response.haslayer(ICMP) and response.getlayer(ICMP).type == 0:
            print(f"IP {host} is open. \n")
            self.put_in_list(host, True)

    @staticmethod
    def get_local_ip():
        """
        Get the local IP address of the machine.
        """
        try:
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            temp_socket.connect(("8.8.8.8", 80))
            local_ip = temp_socket.getsockname()[0]
            temp_socket.close()
            return local_ip
        except socket.error:
            return "Unable to determine IP address"

    def put_in_list(self, ip_address, flag):
        """Create a new Ip object with the given IP address and add it to the list if the flag is True."""
        if flag:
            print(f"adding {ip_address}  to the list.\n")
            self.local_ips.append(ip_address)

    def check_ports_for_ip(self):
        for i, ip in enumerate(self.local_ips):
            print(f"for ip {ip.get_ip()}")
            threads = []
            for p in range(20, 1024):
                t = Thread(target=self.check_port, args=(ip.get_ip(), i, p,))
                t.start()
                threads.append(t)
            count = 0
            for t in threads:
                t.join()
                count += 1
                if count == 30:
                    sleep(2)
        self.local_ips_objects = self.local_ips

    def check_port(self, host: Ip, index, port):
        syn_segment = TCP(dport=port, seq=123, flags="S")
        syn_packet = IP(dst=host) / syn_segment  # stack  them together
        response = sr1(syn_packet, timeout=2, verbose=0)

        if response is None or port == 23:
            print(f"No response from port {port}\n")
        elif response.haslayer(TCP) and response[TCP].flags:
            flags = response[TCP].flags
            if "SA" in str(flags):
                print(f"Port {port} is open")
                self.local_ips[index].set_next_port(str(port))
            elif "R" in str(flags):
                print(f"Port {port} is closed")
            else:
                print(f"Port {port} is filtered")
                self.local_ips[index].set_next_port(str(port))

    def printall(self):
        for ip in self.local_ips_objects:
            print("For IP number " + str(ip.get_ip()) + ", these ports are open:")
            self.append_to_summary("For IP number " + str(ip.get_ip()) + ", these ports are open:")
            if len(ip.portlist) == 0:
                print("No ports are open for this entity.")
                self.append_to_summary("No ports are open for this entity.")
            else:
                for port in ip.portlist:
                    print(str(port) + " ,")
                    self.append_to_summary(str(port) + " ,")
            self.append_to_summary("these are the services that are open:")
            if(len(ip.service_list)) == 0:
                self.append_to_summary("didn't match no services")
            else:
                for service in ip.service_list:
                    print(service)
                    self.append_to_summary(service + " ,")

    def add_services(self):
        for i, ip in enumerate(self.local_ips):
            if len(ip.get_port_list()) != 0:
                self.local_ips[i] = IpFactory.factory_ip(ip)
        self.local_ips_objects = self.local_ips
        self.printall()

