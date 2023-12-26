import datetime
import json
import nmap
from rich.table import Table
from rich import print

class PortScanner:
    """
    This class provides methods for scanning specified ports on a target using Nmap.

    Attributes:
    - target: IP address or hostname of the target.
    - ports: List of ports to scan.
    - scan_v: Nmap PortScanner object.
    - results: Dictionary to store scan results.
    - cli_output: String to store the command-line output.

    Methods:
    1. __init__(self, target):
        - Initializes the instance with the provided target IP address or hostname and sets up default ports.

    2. scan_ports(self):
        - Scans the specified ports on the target using Nmap.
        - Updates the results dictionary with port states.
        - Prints the command-line output during the scan.
        - Returns the results dictionary.
    """

    def __init__(self, target):
        self.target = target
        self.ports = [20, 21, 22, 23, 25, 69, 80, 139, 443, 445, 623, 3306, 3389, 5900, 8080, 27020]
        self.scan_v = nmap.PortScanner()
        self.results = {}
        self.cli_output = ""

    def scan_ports(self):        
        try:
            portscan = self.scan_v.scan(self.target)
            host_state = portscan["scan"][list(portscan["scan"])[0]]["status"]["state"]
            if host_state == "up":
                for port in self.ports:
                    portscan = self.scan_v.scan(self.target, str(port))
                    state = portscan["scan"][list(portscan["scan"])[0]]["tcp"][port]["state"]
                    regel = f"Poort {port} is {state}\n"
                    self.cli_output += regel
                    self.results[str(port)] = str(state)

            else:
                regel = f"Host {self.target} is {host_state}"
                self.cli_output += regel
                self.results["host"] = str(host_state)

        except Exception as e:
            host_state = "down"
            regel = f"Host {self.target} is {host_state}"
            self.cli_output += regel
            self.results["host"] = str(host_state)

        print(self.cli_output)
        return self.results
    
    def write_output_to_file(self, result_json):
        current_time = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        file_name = f"portScan_results{current_time}.json"
        with open(file_name, "w") as file:
            json.dump(result_json, file, indent=4)
        print(f"Output written to file: {file_name}")

if __name__ == "__main__":
    targetL = "127.0.0.1"  # Replace with your target IP address
    scanner = PortScanner(targetL)
    scanner.scan_ports()
