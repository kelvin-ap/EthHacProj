import datetime
import json
import requests


def write_output_to_json_file(name, result_json):
        current_time = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        file_name = f"./results/{name}_results{current_time}.json"
        with open(file_name, "w") as file:
            if isinstance(result_json, requests.structures.CaseInsensitiveDict):
                json.dump(dict(result_json), file, indent=4)
            else:
                json.dump(result_json, file, indent=4)
        print(f"Output written to file: {file_name}")

def write_credentials_to_text_file(name, url, credentials):
		current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
		filename = f"./results/{name}_results_{current_time}.txt"
		with open(filename, 'a') as file:
			file.write(f"Site: {url}\n")
			file.write(f"Username: {credentials['username']}\n")
			file.write(f"Password: {credentials['password']}\n")
			file.write(f"Time: {current_time}\n")
			file.write("\n")