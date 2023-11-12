from scapy.all import srp, Ether, ARP, IP, TCP, sniff, sr1
from scapy.all import *
from scapy.layers.inet import IP, ICMP
import  json, nmap, argparse
import HostDiscoVE
import nmap

class NetworkScanner:
    def __init__(self):
        self.results = {}

    # ip_range format = 192.168.0.0/24
    def host_discovery(self, ip_range):
        # Use HostDiscoVE module to scan the network for hosts
        discovered_hosts = HostDiscoVE.scan_network(ip_range)
        print("Host discovery done")
        self.results['Hosts'] = discovered_hosts
        return discovered_hosts

    def service_discovery(self, hosts):
        open_ports = {}

        # Specify popular ports for scanning
        popular_ports = [22, 80, 443, 21, 23, 25, 110, 143, 3306, 8080]

        for host in hosts:
            ip_address = host['ip']
            mac_address = host['mac']

            open_ports[ip_address] = []

            for port in popular_ports:
                # Create a TCP packet to check if the port is open
                packet = Ether(dst=mac_address)/IP(dst=ip_address)/TCP(dport=port, flags="S")
                ans = srp1(packet, timeout=1, verbose=0)

                if ans and ans.haslayer(TCP) and ans.getlayer(TCP).flags == 0x12:
                    open_ports[ip_address].append(port)

        self.results['open_ports'] = open_ports
        print("Service discovery done")
        return open_ports

    # Unreliable
    def remote_os_detection(self, hosts):
        os_info = {}

        for host in hosts:
            os_info[host['ip']] = []  # Corrected the dictionary key
            pack = IP(dst=host['ip'])/ICMP()
            resp = sr1(pack, timeout=3)
            if resp:
                if IP in resp:
                    ttl = resp.getlayer(IP).ttl
                    if ttl <= 64:
                        os = 'Linux/Unix'
                    elif ttl > 64:
                        os = 'Windows'
                    else:
                        os = 'Not Found'
                    os_info[host['ip']].append(os)
                print(f'\n\nTTL = {ttl} \n*{os}* Operating System is Detected \n\n')
        self.results['os_info'] = os_info
        print("Remote OS detection done")
        return os_info
    
    
    # # Alternative method to detect OS with Nmap, doesn't work tho
    # def remote_os_detection(self, hosts):
    #     os_info = {}

    #     for host in hosts:
    #         os_info[host] = []
    #         detected_os = self.detect_os(host)
    #         os_info[host].append(detected_os)
    #         print(f'\n\n*{detected_os}* Operating System is Detected for {host}\n\n')

    #     self.results['os_info'] = os_info
    #     print("remote_os_detection done")
    #     return os_info

    # def detect_os(self, host):
    #     nm = nmap.PortScanner()
    #     nm.scan(hosts=host, arguments='-O')

    #     if 'osclass' in nm[host]:
    #         # Extract the detected OS information
    #         os_info = nm[host]['osclass'][0]['osfamily']
    #         return os_info
    #     else:
    #         return 'Not Found'

    def pcap_analysis(self, hosts):
        http_traffic = {}

        def analyze_http(pkt):
            if pkt.haslayer(TCP) and pkt.haslayer('Raw'):
                load = pkt.getlayer('Raw').load.decode('utf-8', errors='ignore').lower()
                if 'http' in load:
                    for host in hosts:
                        if host['ip'] == pkt[IP].src:
                            if host['ip'] not in http_traffic:
                                http_traffic[host['ip']] = []
                            http_traffic[host['ip']].append(load)

        # Use Scapy's sniff function to capture and analyze network traffic
        sniff(prn=analyze_http, store=0, timeout=10)
        self.results['http_traffic'] = http_traffic
        print("PCAP analysis done")
        return http_traffic

    def run(self, ip_range):
        full_hosts = self.host_discovery(ip_range)
        hosts = [host['ip'] for host in full_hosts]
        print(hosts)
        self.service_discovery(full_hosts)
        self.remote_os_detection(full_hosts)  # Corrected the argument
        self.pcap_analysis(full_hosts)
        print("Run done")

        # Save the results in a JSON file
        with open('scapy_script.json', 'w') as f:
            json.dump(self.results, f, indent=4)
        print("Scan complete. Results saved in 'scapy_script.json'")
        return self.results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Network Scanner')
    parser.add_argument('--ip_range', help='IP range to scan for hosts')
    args = parser.parse_args()

    if args.ip_range:
        scanner = NetworkScanner()
        results = scanner.run(args.ip_range)
        with open('results.json', 'w') as f:
            json.dump(results, f, indent=4)
        print("Scan complete. Results saved in 'results.json'.")
    else:
        print("Please provide an IP range. Use --ip_range <ip_range>.")
