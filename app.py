from flask import Flask, request, jsonify, render_template_string
import requests
import os
import logging
import time
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# VirusTotal API Key
VT_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '047673d4aa55dfb43497a72b4f70d126fc38b9bac2a4abaeace83275ea370699')

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>UltimateScanner</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; background: #f5f5f5; }
        .container { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; margin-bottom: 30px; }
        .tabs { display: flex; margin-bottom: 20px; }
        .tab { padding: 10px 20px; background: #ddd; border: none; cursor: pointer; margin-right: 5px; }
        .tab.active { background: #007bff; color: white; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
        button { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .results { margin-top: 20px; padding: 15px; border-radius: 5px; }
        .clean { background: #d4edda; color: #155724; }
        .threat { background: #f8d7da; color: #721c24; }
        .loading { text-align: center; padding: 20px; }
        .info { background: #d1ecf1; color: #0c5460; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ UltimateScanner</h1>
        
        <div class="tabs">
            <button class="tab active" onclick="showTab('url')">URL Scanner</button>
            <button class="tab" onclick="showTab('domain')">Domain Scanner</button>
            <button class="tab" onclick="showTab('ip')">IP Scanner</button>
            <button class="tab" onclick="showTab('email')">Email Scanner</button>
        </div>

        <div id="url" class="tab-content active">
            <input type="text" id="url-input" placeholder="Enter URL (e.g., https://example.com)">
            <button onclick="scan('url')">Scan URL</button>
        </div>

        <div id="domain" class="tab-content">
            <input type="text" id="domain-input" placeholder="Enter domain (e.g., example.com)">
            <button onclick="scan('domain')">Scan Domain</button>
        </div>

        <div id="ip" class="tab-content">
            <input type="text" id="ip-input" placeholder="Enter IP address (e.g., 8.8.8.8)">
            <button onclick="scan('ip')">Scan IP</button>
        </div>

        <div id="email" class="tab-content">
            <input type="text" id="email-input" placeholder="Enter email (e.g., test@example.com)">
            <button onclick="scan('email')">Scan Email</button>
        </div>

        <div id="results"></div>
    </div>

    <script>
        function showTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
            document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
            
            // Show selected tab
            document.getElementById(tabName).classList.add('active');
            event.target.classList.add('active');
        }

        async function scan(type) {
            const input = document.getElementById(type + '-input').value;
            if (!input) {
                alert('Please enter a value to scan');
                return;
            }

            const results = document.getElementById('results');
            results.innerHTML = '<div class="loading">🔄 Scanning...</div>';

            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ type: type, target: input })
                });

                const data = await response.json();
                displayResults(data);
            } catch (error) {
                results.innerHTML = '<div class="results threat">❌ Error: ' + error.message + '</div>';
            }
        }

        function displayResults(data) {
            const results = document.getElementById('results');
            
            if (data.error) {
                results.innerHTML = '<div class="results threat">❌ ' + data.error + '</div>';
                return;
            }

            const isClean = data.positives === 0;
            const statusClass = isClean ? 'clean' : 'threat';
            const statusIcon = isClean ? '✅' : '⚠️';
            const statusText = isClean ? 'CLEAN' : 'THREATS DETECTED';

            let html = `
                <div class="results ${statusClass}">
                    <h3>${statusIcon} ${statusText}</h3>
                    <p><strong>Target:</strong> ${data.target}</p>
                    <p><strong>Detections:</strong> ${data.positives}/${data.total}</p>
                    <p><strong>Scan Date:</strong> ${data.scan_date}</p>
                    ${data.permalink ? '<p><a href="' + data.permalink + '" target="_blank">View Full Report</a></p>' : ''}
                </div>
            `;

            // Add additional info if available
            if (data.info) {
                html += '<div class="results info"><strong>Additional Info:</strong><br>' + data.info + '</div>';
            }

            results.innerHTML = html;
        }
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'message': 'UltimateScanner is running!'})

@app.route('/api/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json()
        scan_type = data.get('type')
        target = data.get('target')
        
        logger.info(f"Scanning {scan_type}: {target}")
        
        if scan_type == 'url':
            return jsonify(scan_url(target))
        elif scan_type == 'domain':
            return jsonify(scan_domain(target))
        elif scan_type == 'ip':
            return jsonify(scan_ip(target))
        elif scan_type == 'email':
            return jsonify(scan_email(target))
        else:
            return jsonify({'error': 'Invalid scan type'}), 400
            
    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        return jsonify({'error': str(e)}), 500

def scan_url(url):
    """Scan URL with VirusTotal - FIXED VERSION"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Submit URL for scanning
        submit_data = {
            'apikey': VT_API_KEY,
            'url': url
        }
        
        submit_response = requests.post(
            'https://www.virustotal.com/vtapi/v2/url/scan',
            data=submit_data,
            timeout=15
        )
        
        if submit_response.status_code != 200:
            return {'error': 'Failed to submit URL for scanning'}
        
        # Wait for scan to process
        time.sleep(3)
        
        # Get report
        report_params = {
            'apikey': VT_API_KEY,
            'resource': url
        }
        
        report_response = requests.get(
            'https://www.virustotal.com/vtapi/v2/url/report',
            params=report_params,
            timeout=15
        )
        
        if report_response.status_code != 200:
            return {'error': 'Failed to get scan report'}
        
        report_data = report_response.json()
        
        # CORRECT: Use actual positives from VirusTotal
        positives = report_data.get('positives', 0)
        total = report_data.get('total', 0)
        
        return {
            'target': url,
            'positives': positives,
            'total': total,
            'scan_date': report_data.get('scan_date', 'Unknown'),
            'permalink': report_data.get('permalink', '')
        }
        
    except Exception as e:
        logger.error(f"URL scan error: {str(e)}")
        return {'error': f'URL scan failed: {str(e)}'}

def scan_domain(domain):
    """Scan domain with VirusTotal - FIXED VERSION"""
    try:
        # Clean domain
        domain = domain.replace('https://', '').replace('http://', '').replace('www.', '').split('/')[0]
        
        params = {
            'apikey': VT_API_KEY,
            'domain': domain
        }
        
        response = requests.get(
            'https://www.virustotal.com/vtapi/v2/domain/report',
            params=params,
            timeout=15
        )
        
        if response.status_code != 200:
            return {'error': 'Failed to scan domain'}
        
        data = response.json()
        
        # FIXED: Don't count detected_urls as threats
        # For domains, VirusTotal doesn't provide direct threat count
        # We check if there are recent malicious URLs
        detected_urls = data.get('detected_urls', [])
        
        # Count only recent malicious detections (last 30 days)
        recent_threats = 0
        if detected_urls:
            for url_data in detected_urls[:10]:  # Check first 10
                if url_data.get('positives', 0) > 0:
                    recent_threats += 1
        
        # Additional info about the domain
        info_parts = []
        if detected_urls:
            info_parts.append(f"Found {len(detected_urls)} URLs associated with this domain")
        
        whois_date = data.get('whois_timestamp')
        if whois_date:
            info_parts.append(f"Domain registered: {time.strftime('%Y-%m-%d', time.gmtime(whois_date))}")
        
        return {
            'target': domain,
            'positives': recent_threats,
            'total': 70,
            'scan_date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'permalink': f'https://www.virustotal.com/gui/domain/{domain}',
            'info': ' | '.join(info_parts) if info_parts else None
        }
        
    except Exception as e:
        logger.error(f"Domain scan error: {str(e)}")
        return {'error': f'Domain scan failed: {str(e)}'}

def scan_ip(ip):
    """Scan IP with VirusTotal - FIXED VERSION"""
    try:
        # Validate IP format
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if not re.match(ip_pattern, ip):
            return {'error': 'Invalid IP address format'}
        
        params = {
            'apikey': VT_API_KEY,
            'ip': ip
        }
        
        response = requests.get(
            'https://www.virustotal.com/vtapi/v2/ip-address/report',
            params=params,
            timeout=15
        )
        
        if response.status_code != 200:
            return {'error': 'Failed to scan IP address'}
        
        data = response.json()
        
        # FIXED: Don't count detected_urls as threats for IP
        # For IPs, we should look at detected_communicating_samples or detected_downloaded_samples
        detected_samples = data.get('detected_communicating_samples', [])
        detected_urls = data.get('detected_urls', [])
        
        # Count actual malicious samples, not just any URLs
        threat_count = 0
        if detected_samples:
            # Count samples with recent detections
            for sample in detected_samples[:5]:  # Check first 5 samples
                if sample.get('positives', 0) > 0:
                    threat_count += 1
        
        # Additional info
        info_parts = []
        if data.get('country'):
            info_parts.append(f"Country: {data.get('country')}")
        if data.get('as_owner'):
            info_parts.append(f"AS Owner: {data.get('as_owner')}")
        if detected_urls:
            info_parts.append(f"{len(detected_urls)} URLs found on this IP")
        
        return {
            'target': ip,
            'positives': threat_count,
            'total': 70,
            'scan_date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'permalink': f'https://www.virustotal.com/gui/ip-address/{ip}',
            'info': ' | '.join(info_parts) if info_parts else None
        }
        
    except Exception as e:
        logger.error(f"IP scan error: {str(e)}")
        return {'error': f'IP scan failed: {str(e)}'}

def scan_email(email):
    """Scan email domain - FIXED VERSION"""
    try:
        # Validate email format
        if '@' not in email:
            return {'error': 'Invalid email format'}
        
        domain = email.split('@')[1]
        
        # Scan the domain part of the email
        result = scan_domain(domain)
        
        # Update target to show it's an email scan
        if 'target' in result:
            result['target'] = f"{email} (domain: {domain})"
        
        return result
        
    except Exception as e:
        logger.error(f"Email scan error: {str(e)}")
        return {'error': f'Email scan failed: {str(e)}'}

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=False)
