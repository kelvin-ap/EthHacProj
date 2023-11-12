import nmap

scanner = nmap.PortScanner()
scanner_ip = scanner.scan("google.com", "80", "-v --version-all")
print(type(scanner_ip))
print(scanner_ip)