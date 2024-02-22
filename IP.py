
from Services import Protocol

from typing import List


class Ip:
    # Constructor
    def __init__(self, Ip_address: str, portlist: List[str]):
        self.Ip_address = Ip_address
        self.portlist = portlist.copy()
        self.service_list = []

    # Add new open port
    def set_next_port(self, port: str):
        self.portlist.append(port)

    # Returns ip address
    def get_ip(self):
        return self.Ip_address

    # Returns open ports list
    def get_port_list(self):
        return self.portlist

    # Prints all open ports for the ip address
    def print_ip(self):
        print("For IP number " + self.Ip_address + ", these ports are open:")
        if len(self.portlist) == 0:
            print("None")
        else:
            for port in self.portlist:
                print(port)


class IpFactory:

    @staticmethod
    def factory_ip(ip):
        # Use of the class name to call the static method _get_services
        service_list = IpFactory._get_services(ip.get_port_list())
        if service_list:
            # If service_list is not empty, add services to the ip and return it
            return add_service(ip, service_list)


    @staticmethod
    def _get_services(portlist: List[str]) -> List[str]:
        service_list = []

        # Checking if the ports for each protocol are a subset of the given portlist
        if set(Protocol.FTP.value).issubset(set(portlist)):
            service_list.append("FTP")
        if set(Protocol.FTPS.value).issubset(set(portlist)):
            service_list.append("FTPS")
        if set(Protocol.HTTP.value).issubset(set(portlist)):
            service_list.append("HTTP")
        if set(Protocol.SMB.value).issubset(set(portlist)):
            service_list.append("SMB")
        if set(Protocol.SSH.value).issubset(set(portlist)):
            service_list.append("SSH")
        if set(Protocol.Telnet.value).issubset(set(portlist)):
            service_list.append("Telnet")
        if set(Protocol.SMTP.value).issubset(set(portlist)):
            service_list.append("SMTP")
        if set(Protocol.DNS.value).issubset(set(portlist)):
            service_list.append("DNS")
        if set(Protocol.DHCP.value).issubset(set(portlist)):
            service_list.append("DHCP")
        if set(Protocol.HTTPS.value).issubset(set(portlist)):
            service_list.append("HTTPS")
        if set(Protocol.IMAP.value).issubset(set(portlist)):
            service_list.append("IMAP")
        if set(Protocol.Kerberos_Server.value).issubset(set(portlist)):
            service_list.append("Kerberos Server")

        return service_list


def add_service(ip, service_list):
    # Assigning the list of services to the ip object's service_list attribute
    ip.service_list = service_list.copy()
    return ip

