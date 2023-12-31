import datetime
import json
import whois
from rich.table import Table
from rich import print
from .output import write_output_to_json_file

class WhoIsInfo:
    """
    This class provides methods for retrieving and displaying WHOIS information for a given domain name.

    Attributes:
    - domain_name: The domain name for which WHOIS information is retrieved.
    - domain_info: WHOIS information for the specified domain.

    Methods:
    1. __init__(self, domain_name):
        - Initializes the instance with the provided domain name and sets domain_info to None.

    2. format_datetime_for_html(self, dt):
        - Helper method to format a datetime object as a string for HTML display.

    3. get_domain_info(self):
        - Retrieves WHOIS information for the specified domain.
        - Filters and formats the information for display in a table.
        - Returns a dictionary with the formatted information.
    """

    def __init__(self, domain_name):
        self.domain_name = domain_name
        self.domain_info = None

    def format_datetime_for_html(self, dt):
        # Format the datetime object as a string for HTML display
        return dt.strftime("%Y-%m-%d")

    def get_domain_info(self):
        try:
            self.domain_info = whois.whois(self.domain_name)
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
            filtered_info = {field: getattr(self.domain_info, field, 'N/A') for field in fields_to_keep}

            html_display_info = {}
            for key, value in filtered_info.items():
                if isinstance(value, list):
                    value = ",".join(map(str, value))
                elif isinstance(value, datetime.datetime):
                    value = self.format_datetime_for_html(value)
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
            write_output_to_json_file("whois", html_display_info)
            return html_display_info

        except whois.exceptions.FailedParsingWhoisOutput as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    domain_name = input("Enter a domain name to retrieve WHOIS information: ")
    whois_obj = WhoIsInfo(domain_name).get_domain_info()