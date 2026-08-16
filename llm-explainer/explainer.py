"""
LLM Explainability Pipeline — Stage 10 (Appendix F)
7005SCN SOC Training Platform

Polls the Wazuh API for recent alerts, sends each new one to a locally
hosted LLM (via Ollama) for a plain-English explanation, and saves the
result to a timestamped file.

Run with: python explainer.py
Stop with: Ctrl+C
"""

import os
import time
import json
import urllib3
from datetime import datetime, timedelta

import requests
from dotenv import load_dotenv

# Wazuh's default install uses a self-signed cert; suppress the
# resulting warning noise since this is a closed lab network.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

LLM_MODEL = os.getenv("LLM_MODEL", "llama3.2:3b")
LLM_ENDPOINT = os.getenv("LLM_ENDPOINT", "http://localhost:11434/api/chat")
WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "https://10.0.1.10:9200")
WAZUH_INDEXER_USER = os.getenv("WAZUH_INDEXER_USER", "admin")
WAZUH_INDEXER_PASS = os.getenv("WAZUH_INDEXER_PASS", "")

POLL_INTERVAL_SECONDS = 30
ALERTS_LOOKBACK_MINUTES = 120
ALERTS_PER_CYCLE = 5

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "outputs")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Track alert IDs already explained this run, so the same alert isn't
# re-sent to the LLM every 30s while it's still inside the lookback window.
seen_alert_ids = set()


#def get_wazuh_token():
 # Authenticate to the Wazuh API and return a JWT bearer token.
  #  resp = requests.post(
   #     f"{WAZUH_API_URL}/security/user/authenticate",
    #    auth=(WAZUH_API_USER, WAZUH_API_PASS),
     #   verify=False,
      #  timeout=15,
    #)
    #resp.raise_for_status()
    #return resp.json()["data"]["token"]


def fetch_recent_alerts():
    """Fetch the most recent alerts from the last ALERTS_LOOKBACK_MINUTES."""
    query = {
        "size": ALERTS_PER_CYCLE,
        "sort": [{"timestamp": "desc"}],
        "query": {
            "range": {
                "timestamp": {
                    "gte": f"now-{ALERTS_LOOKBACK_MINUTES}m"
                 }
            }
       }
    }
    resp = requests.post(
        f"{WAZUH_INDEXER_URL}/wazuh-alerts-*/_search",
        auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASS),
        json=query,
        verify=False,
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    hits = data.get("hits", {}).get("hits", [])
    return [hit["_source"] for hit in hits]


def build_prompt(alert):
    """Build the structured plain-English explanation prompt for one alert."""
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})

    alert_summary = {
        "rule_id": rule.get("id"),
        "rule_level": rule.get("level"),
        "rule_description": rule.get("description"),
        "agent_name": agent.get("name"),
        "agent_ip": agent.get("ip"),
        "timestamp": alert.get("timestamp"),
        "full_log": alert.get("full_log", "")[:500],  # cap length
    }

    return f"""You are explaining a cybersecurity alert to someone with zero \
technical or IT background — for example, a small business owner.

Alert data (do not invent anything not shown here):
{json.dumps(alert_summary, indent=2)}

Write your explanation using exactly these five section headers, each \
followed by 1-3 plain sentences. Do NOT use any of these words or their \
abbreviations: SIEM, HIDS, TCP, CVE, payload, rule ID, signature. Base \
every statement only on the alert data above.

ATTACK TYPE:
TARGETED MACHINE:
WHAT THE ATTACKER DID:
WHAT THE SOC DETECTED:
WHAT YOU SHOULD DO NOW:
"""


def call_local_llm(prompt):
    """Send the prompt to the local Ollama chat endpoint and return the reply."""
    resp = requests.post(
        LLM_ENDPOINT,
        json={
            "model": LLM_MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
        },
        timeout=240,  # local CPU inference can be slow, especially first call
    )
    resp.raise_for_status()
    data = resp.json()
    return data.get("message", {}).get("content", "").strip()


def save_explanation(alert, explanation):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(OUTPUT_DIR, f"explanation_{timestamp}.txt")
    with open(filename, "w") as f:
        f.write(f"Alert ID: {alert.get('id', 'unknown')}\n")
        f.write(f"Rule: {alert.get('rule', {}).get('description', 'unknown')}\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n")
        f.write("-" * 60 + "\n\n")
        f.write(explanation)
    return filename


def main():
    print(f"LLM Explainer running. Polling Wazuh every {POLL_INTERVAL_SECONDS} seconds...")
    print(f"Model: {LLM_MODEL} | Wazuh: {WAZUH_INDEXER_URL}\n")

    while True:
        try:
            alerts = fetch_recent_alerts()

            new_alerts = [a for a in alerts if a.get("id") not in seen_alert_ids]

            if not new_alerts:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] No new alerts.")
            for alert in new_alerts:
                alert_id = alert.get("id", "unknown")
                rule_desc = alert.get("rule", {}).get("description", "unknown")
                print(f"[{datetime.now().strftime('%H:%M:%S')}] New alert: {rule_desc}")

                prompt = build_prompt(alert)
                explanation = call_local_llm(prompt)

                print("\n" + "=" * 60)
                print(explanation)
                print("=" * 60 + "\n")

                filename = save_explanation(alert, explanation)
                print(f"Saved to {filename}\n")

                seen_alert_ids.add(alert_id)

        except requests.exceptions.RequestException as exc:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Request error: {exc}")
        except Exception as exc:  # noqa: BLE001 — keep the poll loop alive
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Unexpected error: {exc}")

        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
