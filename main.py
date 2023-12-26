import subprocess
from flask import Flask, render_template, request, jsonify

import scripts

app = Flask(__name__)

@app.route('/')
def index():
    results_json = None
    return render_template('index.html', results_json=results_json)

@app.route('/run_web_script', methods=['POST'])
def run_web_script():
    user_input = request.form.get('website')
    results = scripts.ResponseInfo(user_input).get_location_info()
    return render_template('index.html', results_json=results)

@app.route('/get_sec_headers', methods=['POST'])
def get_sec_headers():
    target = request.form.get('headers')
    results_json = scripts.ResponseInfo(target).get_headers()
    return render_template('index.html', results_json=results_json)

@app.route('/portscan', methods=['POST'])
def run_target_script():
    target = request.form.get('target')
    results = scripts.PortScanner(target).scan_ports()
    return render_template('index.html', results_json=results)

@app.route('/dns_sec_script', methods=['POST'])
def dns_sec_script():
    domain = request.form.get('domain')
    results = scripts.DnsResolver(domain).resolve_ip()
    return render_template('index.html', results_json=results)

@app.route('/whois_script', methods=['POST'])
def whois_script():
    domain = request.form.get('domain')
    results_json = scripts.WhoIs(domain).get_domain_info()
    return render_template('index.html', results_json=results_json)

@app.route('/scapy_script', methods=['POST'])
def scapy_script():
    IPRange = request.form.get('ipRange')
    Scan = scripts.NetworkScanner()
    results_json = Scan.run(IPRange)
    return render_template('index.html', results_json=results_json)

# CHECK IF THIS STILL WORKS
@app.route('/arperMITM_script', methods=['POST'])
def arper_run():
    # 3 input fields
    victim = request.form.get('victim')
    gateway = request.form.get('gateway')
    interface = request.form.get('interface')
    attack = scripts.Arper(victim, gateway, interface)
    results_json = attack.run()
    return render_template('index.html', results_json=results_json)

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

 # CHECK IF THIS STILL WORKS   
@app.route('/sniffForCredentials_script', methods=['POST'])
def sniff():
    port1 = request.form.get('port1')
    port2 = request.form.get('port2')
    results = scripts.Sniffer(port1, port2).sniff_for_credentials()

    results_dict = {
        'results': results
    }
    return render_template('index.html', results_json=results_dict)

@app.route('/bruteforce_script', methods=['POST'])
def bruteforce():
    url = request.form.get('url') or None
    username = request.form.get('username') or None
    password_file = request.form.get('passwordfile') or None
    login_failed_string = request.form.get('login_failed_string') or None
    cookie_value = request.form.get('cookie_value') or None

    if not url and not username and not password_file and not login_failed_string and not cookie_value:
        results_json = scripts.Bruteforce().cracking()
    else:
        params = {}
        if url:
            params['url'] = url
        if username:
            params['username'] = username
        if password_file:
            params['password_file'] = password_file
        if login_failed_string:
            params['login_failed_string'] = login_failed_string
        if cookie_value:
            params['cookie_value'] = cookie_value

        results_json = scripts.Bruteforce(**params).cracking()
    
    return render_template('index.html', results_json=results_json)

@app.route('/ssh_bruteforce_script', methods=['POST'])
def ssh_bruteforce():
    host = request.form.get('host') or None
    username = request.form.get('username') or None
    threads = request.form.get('threads') or None
    port = request.form.get('port') or None
    password_file = request.form.get('passwordfile') or None

    if not host and not username and not threads and not port and not password_file:
        results_json = scripts.SSHBruteForce().run()
    else:
        params = {}
        if host:
            params['url'] = host
        if username:
            params['username'] = username
        if threads:
            params['threads'] = password_file
        if port:
            params['port'] = port
        if password_file:
            params['password_file'] = password_file

        results_json = scripts.SSHBruteForce(**params).run()
    
    return render_template('index.html', results_json=results_json)


if __name__ == '__main__':
    app.run(debug=False)
