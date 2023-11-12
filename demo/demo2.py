import nmap
import sys

target = str(sys.argv[1])
ports = [21, 22, 80, 139, 443, 8080]

scan_v = nmap.PortScanner()

print("\nScannen van ", target, " op poorten 21,22,80,139,443 en 8080...\n")
results = ""

for port in ports:
    portscan = scan_v.scan(target, str(port))
    # output is dictionary met informatie over de scan
    # print(portscan)
    # print(
    #     "Poort ",
    #     port,
    #     " is ",
    #     portscan["scan"][list(portscan["scan"])[0]]["tcp"][port]["state"],
    # )
    regel = f"Poort {port} is " + portscan["scan"][list(portscan["scan"])[0]]["tcp"][port]["state"] +"\n"
    results += regel

regel = f"Host {target} is " + portscan["scan"][list(portscan["scan"])[0]]["status"]["state"]
results += regel
# print(
#     "\nHost ",
#     target,
#     " is ",
#     portscan["scan"][list(portscan["scan"])[0]]["status"]["state"],
# )
print(results)
