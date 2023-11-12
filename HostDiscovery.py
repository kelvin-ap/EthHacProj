import ipaddress
import asyncio
from scapy.all import IP, ICMP, sr1, conf

# Script no longer to be continued

conf.verb = 0  # Suppress Scapy output

async def is_host_reachable(ip):
    packet = IP(dst=ip) / ICMP()
    loop = asyncio.get_event_loop()
    
    try:
        response = await loop.run_in_executor(None, lambda: sr1(packet, iface=None, timeout=1, verbose=False))
        if response:
            return True
    except asyncio.TimeoutError:
        pass
    
    return False

async def scan_ip_range(ip_range):
    ip_network = ipaddress.IPv4Network(ip_range, strict=False)
    tasks = []

    for ip in ip_network.hosts():
        ip_str = str(ip)
        print(f"Scanning {ip_str}")
        task = asyncio.create_task(is_host_reachable(ip_str))
        tasks.append(task)

    results = await asyncio.gather(*tasks)
    reachable_hosts = [str(ip) for ip, result in zip(ip_network.hosts(), results) if result]
    unreachable_hosts = [str(ip) for ip, result in zip(ip_network.hosts(), results) if not result]

    return reachable_hosts, unreachable_hosts

if __name__ == "__main__":
    ip_range = "192.168.0.0/16"

    loop = asyncio.get_event_loop()
    reachable, unreachable = loop.run_until_complete(scan_ip_range(ip_range))
    loop.close()

    print("\nReachable hosts:")
    for host in reachable:
        print(host)

    print("\nUnreachable hosts:")
    for host in unreachable:
        print(host)
