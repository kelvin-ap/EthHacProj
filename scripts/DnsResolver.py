import datetime
import json
import dns.resolver
import sys
from .output import write_output_to_json_file

class DnsResolver:
    """
    This class performs DNS resolution and DNSSEC validation for a given domain name.

    Methods:

    1. __init__(self, domain_name):
        - Initializes instance with the provided domain_name.
    
    2. resolve_ip(self):
        - Resolves the IP address for the domain using DNS resolution and performs DNSSEC validation.
        - Prints information about the DNS resolution process.
        - Returns a JSON result indicating the status of the resolution.
    """

    def __init__(self, domain_name):
        self.domain_name = domain_name
        self.resolver = dns.resolver.Resolver()
        self.resolver.use_dnssec = True

    def resolve_ip(self):
        result_json = {}
        try:
            answer = self.resolver.query(self.domain_name, 'A')
            for record in answer:
                print(f'DNS Sec validation OK for [red]{self.domain_name}[reset]: IP=[green]{record.address}')
                result_json[self.domain_name] = "OK"
                write_output_to_json_file("DNSSEC", result_json)
                return result_json
        except dns.resolver.NXDOMAIN:
            print(f'[magenta]Domain not found: {self.domain_name}')
            result_json[self.domain_name] = "Domain not found"
            write_output_to_json_file("DNSSEC", result_json)
            return result_json
        except dns.exception.DNSException as e:
            print(f'[magenta]DNS Resolution error for [red]{self.domain_name}[reset]: [green]{str(e)}')
            result_json[self.domain_name] = "Bad DNS SEC signature"
            write_output_to_json_file("DNSSEC", result_json)
            return result_json

if __name__ == "__main__":
    domain_name = sys.argv[1]
    resolver = DnsResolver(domain_name)
    resolver.resolve_ip()
