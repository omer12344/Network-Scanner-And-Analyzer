from ScanLan import ScanLanSession
from Sniff import SniffSession
email_receiver = str(input("what email you want to get updates to?"))

scan_lan_session = ScanLanSession(email_receiver)
sniff_session = SniffSession(1000, scan_lan_session.local_ips_objects, scan_lan_session.local_ips, email_receiver)
