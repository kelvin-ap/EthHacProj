import sys
import dns.resolver
import rich
from rich.table import Table
from rich import print

def resolve_ip(domain_name):
    resolver = dns.resolver.Resolver()
    resolver.use_dnssec = True
    try:
        answer = resolver.query(domain_name, 'A')
        for record in answer:
            print(f'DNS Sec validation OK for [red]{domain_name}[reset]: IP=[green]{record.address}')
            return f"DNS Sec validation OK for {domain_name}: IP={record.address}"
    except dns.resolver.NXDOMAIN:
        print(f'[magenta]Domain not found: {domain_name}')
        return f"Domain not found: {domain_name}"
    except dns.exception.DNSException as e:
        print(f'[magenta]DNS Resolution error for [red]{domain_name}[reset]: [green]{str(e)}')
        return f"bad DNS SEC signature for {domain_name}"
    # dnssec-failed.org

if __name__ == "__main__":
    resolve_ip(sys.argv[1])