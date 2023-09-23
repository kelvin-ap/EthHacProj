import rich
from rich.table import Table
from rich import print
import requests
import socket
import json
import sys

def get_location_info(url):
    try:
        geef_host = socket.gethostbyname(url)
        print("\nHet ip-adres van [italic red]" + url + "[reset] is: [italic green]" + geef_host + "\n")

        request_twee = requests.get("https://ipinfo.io/" + geef_host + "/json")
        response = json.loads(request_twee.text)

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Header", style="bold red")
        table.add_column("Value", style="bold green")
        for key, value in response.items():
            table.add_row(key, value)
        print(table)

        return response
    except Exception as e:
        return {"error": str(e)}
    
def get_headers(url):
    try:
        request = requests.get("https://" + url)

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Header", style="bold red")
        table.add_column("Value", style="bold green")

        for key, value in request.headers.items():
            table.add_row(key, value)
        print(table)
        return request.headers

    except Exception as e:
        return {"error": str(e)}
    
    # dns resolver
    # whois
