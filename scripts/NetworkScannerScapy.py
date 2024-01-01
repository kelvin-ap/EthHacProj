from functools import partial
import nmap
from scapy.all import srp, Ether, ARP, IP, TCP, sniff, sr1
from scapy.all import *
from scapy.layers.inet import IP, ICMP
from rich.table import Table
from rich import print
import json, argparse
import concurrent.futures

from .os_detection import OsDetector
from .HostDiscoV2 import HostDiscovery
from .PortScan import PortScanner
from .output import write_output_to_json_file

class NetworkScanner:
    """
    This class provides methods for host discovery, service discovery, remote OS detection,
    and pcap analysis on a network using Scapy and Nmap.

    Attributes:
    - results: A dictionary to store the results of the network scan.

    Methods:
    1. __init__(self):
        - Initializes the instance with an empty results dictionary.

    2. host_discovery(self, ip_range):
        - Performs host discovery on the specified IP range using ARP or Nmap.
        - Returns a list of discovered hosts.

    3. service_discovery(self, hosts):
        - Performs service discovery by checking for open ports on each host.
        - Returns a dictionary mapping IP addresses to open ports.

    4. _detect_os(self, host):
        - Helper method to detect the operating system of a remote host.
        - Uses the OsDetector class from os_detection module.
        - Returns a tuple containing the host and the detected OS.

    5. remote_os_detection(self, hosts):
        - Performs remote OS detection for a list of hosts using multithreading.
        - Prints a formatted table of host and OS information.
        - Returns a dictionary mapping host IPs to detected OS.

    6. pcap_analysis(self, hosts):
        - Performs pcap analysis to capture HTTP traffic on the network.
        - Returns a dictionary mapping host IPs to captured HTTP traffic.

    7. run(self, ip_range):
        - Executes the complete network scan including host discovery, service discovery,
          remote OS detection, and pcap analysis.
        - Saves the results in a JSON file.
        - Returns the results dictionary.
    """

    def __init__(self):
        self.results = {}

    # ip_range format = 192.168.0.0/24
    def host_discovery(self, ip_range):
        discovered_hosts = HostDiscovery(ip_range).arp_host_discovery()
        if not discovered_hosts:
            print("No hosts detected with ARP scan. Performing Nmap scan.")
            discovered_hosts = HostDiscovery(ip_range).nmap_host_discovery()
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

    @staticmethod
    def _scan_ports(host):
        t = False
        scanPort = PortScanner(host, t).scan_ports()
        return host, scanPort
    
    def service_discovery(self, hosts):
        results = {}

        with concurrent.futures.ThreadPoolExecutor() as executor:
            # Use partial to create a function with a fixed argument (self)
            futures = {executor.submit(self._scan_ports, host): host for host in hosts}
            
            # Collect the results
            for future in concurrent.futures.as_completed(futures):
                host = futures[future]
                try:
                    scanPort = future.result()[1]
                    results[str(host)] = scanPort
                except Exception as e:
                    results[str(host)] = f"Error: {e}"

        self.results['open_ports'] = results
        print("Port discovery done")
        return results

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
        
        self.service_discovery(hosts)
        self.remote_os_detection(hosts)
        # self.pcap_analysis(full_hosts)
        print("Run done")

        write_output_to_json_file("NetworkScan", self.results)
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
