from enum import Enum


class Protocol(Enum):
    FTP = ["20", "21"]
    FTPS = ["20", "21", "990"]
    SSH = ["22"]
    Telnet = ["23"]
    SMTP = ["25"]
    DNS = ["53"]
    DHCP = ["67", "68"]
    HTTP = ["80"]
    HTTPS = ["443"]
    IMAP = ["143"]
    SMB = ["445"]
    Kerberos_Server = ["88"]

    @staticmethod
    def get_ports_by_name(name):
        """Return the ports of a given protocol name."""
        for protocol in Protocol:
            if protocol.name == name.upper():
                return protocol.value
        return None

    @staticmethod
    def check_port(port):
        """Check if a given port is associated with any protocol."""
        for protocol in Protocol:
            if port in protocol.value:
                return True
        return False

    @classmethod
    def list_all_protocols(cls):
        """List all protocols and their ports."""
        return {protocol.name: protocol.value for protocol in cls}

    @staticmethod
    def find_protocol_by_port(port):
        """Find which protocol(s) a given port is associated with."""
        protocols = []
        for protocol in Protocol:
            if port in protocol.value:
                protocols.append(protocol.name)
        return protocols if protocols else None

