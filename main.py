import json
import logging
import os
import subprocess
from flask import Flask, render_template, request, jsonify
import websiteLookUp
import PortScan
import DnsResolver
import WhoIs
import sniffer
from NetworkScannerScapy import NetworkScanner

app = Flask(__name__)

@app.route('/')
def index():
    portscan_results = None
    web_results = None
    # headers_results = None
    dns_results = None
    # whois_results = None
    results_json = None
    # return render_template('index.html', whois_results=whois_results, dns_results=dns_results, portscan_results=portscan_results, web_results=web_results, headers_results=headers_results)
    return render_template('index.html', dns_results=dns_results, portscan_results=portscan_results, web_results=web_results, results_json=results_json)

@app.route('/run_web_script', methods=['POST'])
def run_web_script():
    user_input = request.form.get('website')
    web_results = websiteLookUp.get_location_info(user_input)
    return render_template('index.html', web_results=web_results)

@app.route('/get_sec_headers', methods=['POST'])
def get_sec_headers():
    target = request.form.get('headers')
    results_json = websiteLookUp.get_headers(target)
    return render_template('index.html', results_json=results_json)

@app.route('/run_target_script', methods=['POST'])
def run_target_script():
    target = request.form.get('target')
    portscan_results = PortScan.scan_ports(target)
    return render_template('index.html', portscan_results=portscan_results)

@app.route('/dns_sec_script', methods=['POST'])
def dns_sec_script():
    domain = request.form.get('domain')
    dns_results = DnsResolver.resolve_ip(domain)
    return render_template('index.html', dns_results=dns_results)

@app.route('/whois_script', methods=['POST'])
def whois_script():
    domain = request.form.get('domain')
    results_json = WhoIs.get_domain_info(domain)
    return render_template('index.html', results_json=results_json)

@app.route('/scapy_script', methods=['POST'])
def scapy_script():
    IPRange = request.form.get('ipRange')
    Scan = NetworkScanner()
    results_json = Scan.run(IPRange)
    return render_template('index.html', results_json=results_json)

@app.route('/arperMITM_script', methods=['POST']) #upon button press run this
def arper_run():
    # 3 input fields
    victim = request.form.get('victim')
    gateway = request.form.get('gateway')
    interface = request.form.get('interface')

    # Command to run the Arper script with the provided arguments
    command = [
        'python',  # Replace with 'python3' if necessary
        'arper_script.py',  # Replace with the actual script filename
        victim,
        gateway,
        interface
    ]
    
    try:
        # Run the Arper script as a subprocess
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,  # Capture stdout
            stderr=subprocess.STDOUT,  # Capture stderr (redirect to stdout)
            text=True  # Ensure text mode for stdout/stderr
        )
        
        # Capture the output
        output, _ = process.communicate()
        
        # Check the return code to see if the subprocess completed successfully
        return_code = process.returncode
        
        # Prepare the response
        response_data = {
            'output': output,
            'return_code': return_code
        }
        
        # Return the response as JSON
        results_json = jsonify(response_data)
        return render_template('index.html', results_json=results_json)
    
    except Exception as e:
        # Handle any exceptions that may occur during subprocess execution
        return jsonify({'error': str(e)})
    
@app.route('/sniffForCredentials_script', methods=['POST'])
def sniff():
    port1 = request.form.get('port1')
    port2 = request.form.get('port2')
    results = sniffer.sniff_for_credentials(port1, port2)

    results_dict = {
        'results': results
    }
    return render_template('index.html', results_json=results_dict)

if __name__ == '__main__':
    app.run(debug=True)
