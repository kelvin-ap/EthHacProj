from scapy.all import srp, Ether, ARP, IP, TCP, sniff, sr1
from scapy.all import *
from scapy.layers.inet import IP, ICMP
import  json, argparse
import HostDiscoV2
from os_detection import OsDetector
import concurrent.futures
from rich.table import Table
from rich import print

class NetworkScanner:
    def __init__(self):
        self.results = {}

    # ip_range format = 192.168.0.0/24
    def host_discovery(self, ip_range):
        # Use HostDiscoV2 module to scan the network for hosts
        discovered_hosts = HostDiscoV2.arp_host_discovery(ip_range)
        if not discovered_hosts:
            print("No hosts detected with ARP scan. Performing Nmap scan.")
            discovered_hosts = HostDiscoV2.nmap_host_discovery(ip_range)
            list = []
            for host in discovered_hosts:
                list.append(host.ip)
            self.results['nmap'] = list
            print("Host discovery done")
            return discovered_hosts
            
        print("ARP Host discovery done")
        for host in discovered_hosts:
            self.results['ARP ip'] = host.ip
            self.results['ARP mac'] = host.mac

        print("Host discovery done")
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

    @staticmethod
    def _detect_os(host):
        os_detector = OsDetector(host)
        detected_os = os_detector.find_os()
        return host, detected_os

    def remote_os_detection(self, hosts):
        os_info = {}

        with concurrent.futures.ThreadPoolExecutor() as executor:
            # Submit tasks for each host in parallel
            futures = {executor.submit(self._detect_os, host): host for host in hosts}

            # Retrieve results as they become available
            for future in concurrent.futures.as_completed(futures):
                host = futures[future]
                try:
                    detected_os = future.result()[1]
                    os_info[str(host)] = detected_os
                except Exception as e:
                    os_info[str(host)] = f"Error: {e}"

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Header", style="bold red")
        table.add_column("Value", style="bold green")
        for key, value in os_info.items():
            table.add_row(key, value)
        print(table)

        self.results['os_info'] = os_info
        print("Remote OS detection done")
        return os_info

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
        hosts = [host.ip for host in full_hosts]

        # self.service_discovery(full_hosts)
        self.remote_os_detection(hosts)
        # self.pcap_analysis(full_hosts)
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
    else:
        print("Please provide an IP range. Use --ip_range <ip_range>.")
