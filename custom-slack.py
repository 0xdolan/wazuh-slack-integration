#!/var/ossec/venv/bin/python

import json
import re
import sys
from datetime import datetime

import requests

# Slack webhook URLs (Critical, High, Medium)
WEBHOOK_CRITICAL = ""  # replace with your Critical channel webhook
WEBHOOK_HIGH = ""  # replace with your High channel webhook
WEBHOOK_MEDIUM = ""  # replace with your Medium channel webhook

# Excluded Wazuh Rule IDs
excluded_rules: list = []  # Example: ["1002", "5715", "18107"]


def escape_markdown(text):
    """
    Escapes characters used by Slack markdown to avoid unintended formatting.
    Only *, _, `, and ~ are special in Slack and need escaping.
    """
    if not isinstance(text, str):
        text = str(text)
    # Escape only Slack formatting characters: *, _, `, and ~
    return re.sub(r"([*`_~])", r"\\\1", text)


def choose_webhook(level):
    try:
        lvl = int(level)
    except ValueError:
        return WEBHOOK_MEDIUM
    if lvl >= 11:
        return WEBHOOK_CRITICAL
    elif lvl >= 7:
        return WEBHOOK_HIGH
    else:
        return WEBHOOK_MEDIUM


def main():
    if len(sys.argv) < 2:
        print("[ERROR] No alert file path provided.")
        sys.exit(1)
    alert_file = sys.argv[1]
    try:
        with open(alert_file) as f:
            alert = json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to read or parse JSON: {e}")
        sys.exit(1)

    rule_id = alert.get("rule", {}).get("id")
    if rule_id in excluded_rules:
        print(f"[INFO] Skipping excluded rule ID: {rule_id}")
        sys.exit(0)

    data = alert.get("data", {})
    srcuser = data.get("srcuser") or data.get("dstuser") or "unknown"
    srcip = data.get("srcip", "unknown")
    srcport = data.get("srcport", "unknown")
    agent_name = alert.get("agent", {}).get("name", "unknown")
    alert_level = alert.get("rule", {}).get("level", "unknown")
    description = alert.get("rule", {}).get("description", "No description")
    full_log = alert.get("full_log", "No full log available")
    timestamp_raw = alert.get("timestamp", "unknown")

    try:
        dt = datetime.fromisoformat(timestamp_raw.replace("Z", "+00:00"))
        timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        timestamp = timestamp_raw

    # Build Slack message with block formatting
    text = (
        "*:rotating_light: Wazuh Alert Notification*\n\n"
        f"*Time:* `{escape_markdown(timestamp)}`\n"
        f"*Username:* `{escape_markdown(srcuser)}`\n"
        f"*Source IP:* `{escape_markdown(srcip)}`\n"
        f"*Source Port:* `{escape_markdown(srcport)}`\n"
        f"*Agent:* `{escape_markdown(agent_name)}`\n\n"
        f"*Rule ID:* `{escape_markdown(rule_id)}`\n"
        f"*Level:* `{escape_markdown(alert_level)}`\n\n"
        f"*Description:*\n```{escape_markdown(description)}```\n\n"
        f"*Full Log:*\n```{full_log}```"
    )

    vuln = alert.get("vulnerability", {})
    cve_id = vuln.get("cve", "")
    cve_title = vuln.get("title", "")
    if cve_id:
        cve_url = f"https://cti.wazuh.com/vulnerabilities/cves/{cve_id}"
        text += (
            f"\n\n*🛡️ CVE:* `{escape_markdown(cve_id)}`\n"
            f"*Title:* {escape_markdown(cve_title)}\n"
            f"<{escape_markdown(cve_url)}|Details in CTI>"
        )

    webhook_url = choose_webhook(alert_level)
    payload = {"text": text}
    resp = requests.post(webhook_url, json=payload)
    if resp.status_code != 200:
        print(f"[ERROR] Slack response: {resp.status_code} – {resp.text}")


if __name__ == "__main__":
    main()
