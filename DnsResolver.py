import dns.resolver
from rich.table import Table
from rich import print

def resolve_ip(domain_name):
    resolver = dns.resolver.Resolver()
    resolver.use_dnssec = True
    result_json = {}
    try:
        answer = resolver.query(domain_name, 'A')
        for record in answer:
            print(f'DNS Sec validation OK for [red]{domain_name}[reset]: IP=[green]{record.address}')
            result_json[domain_name] = "OK"
            # return f"DNS Sec validation OK for {domain_name}: IP={record.address}"
            return result_json
    except dns.resolver.NXDOMAIN:
        print(f'[magenta]Domain not found: {domain_name}')
        result_json[domain_name] = "Domain not found"
        # return f"Domain not found: {domain_name}"
        return result_json
    except dns.exception.DNSException as e:
        print(f'[magenta]DNS Resolution error for [red]{domain_name}[reset]: [green]{str(e)}')
        result_json[domain_name] = "Bad DNS SEC signature"
        # return f"bad DNS SEC signature for {domain_name}"
        return result_json

# if __name__ == "__main__":
#     resolve_ip(sys.argv[1])