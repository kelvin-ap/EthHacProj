import nmap

class OsDetector:
    """
    This class provides methods for detecting the operating system of a remote host using Nmap.

    Attributes:
    - ip_address: IP address of the remote host.
    - nm: Nmap PortScanner object.

    Methods:
    1. __init__(self, ip_address):
        - Initializes the instance with the provided IP address and creates an Nmap PortScanner object.

    2. find_os(self):
        - Performs OS detection using Nmap on the specified IP address.
        - Returns the detected operating system or an error message.
    """

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
