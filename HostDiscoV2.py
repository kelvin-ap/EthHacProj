from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
import nmap

# arp_host_discovery credit to Ernie de Magtige
class Host:
    def __init__(self, ip, mac):
        self.ip = ip
        self.mac = mac

def scan_ip(current_ip):
    arp_request = ARP(pdst=current_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    hosts = []
    for _, received in answered_list:
        print(f"IP: {received.psrc}", flush=True)
        hosts.append(Host(received.psrc, received.hwsrc))

    return hosts

def arp_host_discovery(subnet):
    network, host_part = subnet.split('/')
    host_part = int(host_part)
    num_addresses = 2 ** (32 - host_part)
    network = list(map(int, network.split('.')))

    hosts = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = []
        for _ in range(1, num_addresses - 1):
            # Calculate the IP address
            current_ip = ".".join(map(str, network))
            print(f"Scanning IP: {current_ip}", flush=True)

            # Submit the current IP for scanning
            futures.append(executor.submit(scan_ip, current_ip))

            # Increment the IP address for the next iteration
            network[3] += 1
            if network[3] > 255:
                network[2] += 1
                network[3] = 0
            if network[2] > 255:
                network[1] += 1
                network[2] = 0
            if network[1] > 255:
                break

        for future in as_completed(futures):
            hosts.extend(future.result())

    return hosts


def nmap_host_discovery(subnet):
    nm = nmap.PortScanner()
    nm.scan(hosts=subnet, arguments='-sn')

    hosts = []
    for host in nm.all_hosts():
        hosts.append(Host(host, None))
        
    return hosts