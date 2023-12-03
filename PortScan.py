import json
import nmap
from rich.table import Table
from rich import print

def scan_ports(targetL):    
    ports = [20, 21, 22, 23, 25, 69,80, 139, 443, 445, 623, 3306,3389, 5900, 8080, 27020]
    scan_v = nmap.PortScanner()
    target = str(targetL)
    results = {}
    cli_output = ""
    
    for port in ports:
        portscan = scan_v.scan(target, str(port))
        regel = f"Poort {port} is " + portscan["scan"][list(portscan["scan"])[0]]["tcp"][port]["state"] +"\n"
        cli_output += regel
        results[str(port)] = str(portscan["scan"][list(portscan["scan"])[0]]["tcp"][port]["state"])
    
    regel = f"Host {target} is " + portscan["scan"][list(portscan["scan"])[0]]["status"]["state"]
    cli_output += regel
    print(cli_output)

    results["host"] = str(portscan["scan"][list(portscan["scan"])[0]]["status"]["state"])

    return results
