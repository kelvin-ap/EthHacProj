import nmap

class OsDetector:
    def __init__(self, ip_address):
        self.ip_address = ip_address
        self.nm = nmap.PortScanner()

    def find_os(self):
        try:
            # Perform OS detection
            self.nm.scan(self.ip_address, arguments='-O')

            # Get the results
            os_guess = self.nm[self.ip_address]['osmatch']

            if os_guess:
                os_name = os_guess[0]['name']
                return os_name
            else:
                return "Unable to determine the operating system."

        except nmap.PortScannerError as e:
            return f"Error: {e}"

if __name__ == "__main__":
    # Replace 'target_ip' with the actual IPv4 address you want to scan
    target_ip = '192.168.0.181'
    
    os_detector = OsDetector(target_ip)
    detected_os = os_detector.find_os()
    
    print(f"Operating System for {target_ip}: {detected_os}")
