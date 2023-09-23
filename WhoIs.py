import datetime
import whois
from rich.table import Table
from rich import print

def format_datetime_for_html(dt):
    # Format the datetime object as a string for HTML display
    return dt.strftime("%Y-%m-%d")

def get_domain_info(domain_name):
    try:
        domain_info = whois.whois(domain_name)
        fields_to_keep = [
            'domain_name',
            'registrar',
            'name',
            'email',
            'creation_date',
            'expiration_date',
            'status',
            'name_servers'
        ]

        # Create a filtered dictionary with the desired fields
        filtered_info = {field: getattr(domain_info, field, 'N/A') for field in fields_to_keep}
        
        html_display_info = {}
        for key, value in filtered_info.items():
            if isinstance(value, list):
                value = ",".join(map(str, value))
            elif isinstance(value, datetime.datetime):
                value = format_datetime_for_html(value)
            html_display_info[key] = value

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Header", style="bold red")
        table.add_column("Value", style="bold green")
        for key, value in filtered_info.items():
            # Convert lists and datetimes to strings for display
            if isinstance(value, list):
                value = "\n".join(map(str, value))
            elif isinstance(value, datetime.datetime):
                value = value.strftime("%Y-%m-%d")
            table.add_row(key, value)
        print(table)

        return html_display_info
        
    except whois.parser.PywhoisError as e:
        print(f"Error: {e}")

# Example usage:
# if __name__ == "__main__":
#     domain_name = input("Enter a domain name to retrieve WHOIS information: ")
#     get_domain_info(domain_name)
