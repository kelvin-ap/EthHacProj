from flask import Flask, render_template, request, jsonify
import websiteLookUp
import PortScan
import DnsResolver
import WhoIs

app = Flask(__name__)

@app.route('/')
def index():
    portscan_results = None
    web_results = None
    headers_results = None
    dns_results = None
    whois_results = None
    return render_template('index.html', whois_results=whois_results, dns_results=dns_results, portscan_results=portscan_results, web_results=web_results, headers_results=headers_results)

@app.route('/run_web_script', methods=['POST'])
def run_web_script():
    user_input = request.form.get('website')
    web_results = websiteLookUp.get_location_info(user_input)
    return render_template('index.html', web_results=web_results)

@app.route('/get_sec_headers', methods=['POST'])
def get_sec_headers():
    target = request.form.get('headers')
    headers_results = websiteLookUp.get_headers(target)
    return render_template('index.html', headers_results=headers_results)

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
    whois_results = WhoIs.get_domain_info(domain)
    return render_template('index.html', whois_results=whois_results)


if __name__ == '__main__':
    app.run(debug=True)
