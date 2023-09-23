import sys
import nmap
import rich
from rich.table import Table
from rich import print

def scan_ports(targetL):
    ports = [21, 22, 80, 139, 443, 8080]
    scan_v = nmap.PortScanner()
    target = str(targetL)
    results = ""
    
    for port in ports:
        portscan = scan_v.scan(target, str(port))
        regel = f"Poort {port} is " + portscan["scan"][list(portscan["scan"])[0]]["tcp"][port]["state"] +"\n"
        results += regel
    
    regel = f"Host {target} is " + portscan["scan"][list(portscan["scan"])[0]]["status"]["state"]
    results += regel
    print(results)
    return results

# if __name__ == "__main__":
#     if len(sys.argv) != 2:
#         print("Usage: python script.py <target>")
#         sys.exit(1)

#     scan_ports(sys.argv[1])
    
#     target = sys.argv[1]
#     scan_results = scan_ports(target)
