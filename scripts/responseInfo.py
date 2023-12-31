import ast
import datetime
from rich.table import Table
from rich import print
import requests
import socket
import json
from .output import write_output_to_json_file, write_credentials_to_text_file

class ResponseInfo:
    """
    This class provides methods for retrieving location information and headers from a given URL.

    Attributes:
    - url: The URL for which information is retrieved.

    Methods:
    1. __init__(self, url):
        - Initializes the instance with the provided URL.

    2. get_location_info(self):
        - Retrieves the IP address and location information for the specified URL.
        - Prints the information in a formatted table.
        - Returns the response as a dictionary.

    3. get_headers(self):
        - Retrieves the headers for the specified URL.
        - Prints the headers in a formatted table.
        - Returns the headers as a dictionary.
    """

    def __init__(self, url):
        self.url = url

    def get_location_info(self):
        try:
            geef_host = socket.gethostbyname(self.url)
            print("\nHet ip-adres van [italic red]" + self.url + "[reset] is: [italic green]" + geef_host + "\n")

            request_twee = requests.get("https://ipinfo.io/" + geef_host + "/json")
            response = json.loads(request_twee.text)

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Header", style="bold red")
            table.add_column("Value", style="bold green")
            for key, value in response.items():
                table.add_row(key, value)
            print(table)
            write_output_to_json_file("location", response)
            return response
        except Exception as e:
            return {"error": str(e)}

    def get_headers(self):
        try:
            request = requests.get("https://" + self.url)
            
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Header", style="bold red")
            table.add_column("Value", style="bold green")

            for key, value in request.headers.items():
                table.add_row(key, value)
            print(table)
            
            write_output_to_json_file("headers", request.headers)
            return request.headers

        except Exception as e:
            return {"error": str(e)}

# Usage example:
if __name__ == "__main__":
    response_info = ResponseInfo("example.com")
    response_info.get_location_info()
    response_info.get_headers()
