# Wazuh 4.12 Slack Alert Integration

![Wazuh Slack Integration](images/wazuh-slack.jpg)

Wazuh is a powerful open-source security platform for threat detection and response. This guide walks you through creating a custom integration script to send Wazuh alerts directly to Slack channels.

> Note: Wazuh ships with a default `slack.py` script located at `/var/ossec/integrations`, but it’s generic and may not meet specific formatting or channel-routing needs. In this guide, we’ll build a tailored solution from scratch.

![Wazuh Slack Alert Sample](images/wazuh-slack-alert-sample.jpg)

---

## 🛠️ Prerequisites

- A Slack workspace with three channels and their webhooks:
  - `critical`
  - `high`
  - `medium`
- Wazuh 4.12 installed
- Basic knowledge of Linux shell and Python

---

## 🔧 Create a Slack Workspace and Channels

- [Create a Slack Workspace](https://slack.com/help/articles/206845317-Create-a-Slack-workspace)
- [Create a Slack Channel](https://slack.com/help/articles/201402297-Create-a-channel)
- [Enable Incoming Webhooks](https://api.slack.com/messaging/webhooks)

Your Slack webhook URL will look like this:

`https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX`

Make sure your webhook URLs are structured like this:
![Webhooks](/images/webhooks.jpg)

---

## 📦 Step 1: Set up Python Virtual Environment in Wazuh

Create a Python virtual environment inside the Wazuh directory (`/var/ossec`) to avoid permission issues and package conflicts.

```bash
mkdir -p /var/ossec/venv
python3 -m venv /var/ossec/venv
source /var/ossec/venv/bin/activate
pip install requests  # or any needed packages
```

## 📁 Step 2: Create Slack Integration Script

Name the script with prefix `custom-`.  
**Location:** `/var/ossec/integrations/custom-slack.py`

````python

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

    text += "\n\n────────────────────────\n"

    webhook_url = choose_webhook(alert_level)
    payload = {"icon_emoji": ":rotating_light:", "username": "Wazuh Alert Notification", "text": text}
    resp = requests.post(webhook_url, json=payload)
    if resp.status_code != 200:
        print(f"[ERROR] Slack response: {resp.status_code} – {resp.text}")


if __name__ == "__main__":
    main()

````

## 🔧 Step 3: Create Shell Wrapper Script

Wazuh calls shell scripts, so create a simple wrapper to call the Python script. It should have the same name of the python file without the `.py` extension.
**Location:** `/var/ossec/integrations/custom-slack`

```bash
#!/bin/sh

# Set the virtual environment Python binary
CUSTOM_PYTHON="/var/ossec/venv/bin/python3"

SCRIPT_PATH_NAME="$0"
DIR_NAME="$(cd "$(dirname "${SCRIPT_PATH_NAME}")"; pwd -P)"
SCRIPT_NAME="$(basename "${SCRIPT_PATH_NAME}")"
PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"

# Run the integration script using custom Python interpreter
${CUSTOM_PYTHON} "${PYTHON_SCRIPT}" "$@"
```

Make both scripts executable and set proper ownership:

```bash
chmod 750 /var/ossec/integrations/custom-slack*
chown root:wazuh /var/ossec/integrations/custom-slack*
```

## Step 4: Configure Integration in `ossec.conf`

- Ensure that `logall_json` is enabled by setting it to `yes` in your `ossec.conf` file:

```xml
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>yes</logall>
    <logall_json>yes</logall_json>
  </global>
</ossec_config>
```

- Add the integration block in `/var/ossec/etc/ossec.conf`:
- The `<name>` tag value (`custom-slack`) must exactly match the name of your wrapper script.

```xml
<ossec_config>
    <integration>
    <name>custom-slack</name>
    <alert_format>json</alert_format>
    </integration>
</ossec_config>
```

Restart Wazuh to apply changes:

```bash
systemctl restart wazuh-manager.service
```

## ✅ Step 6: Test the Integration

Test manually with an alert JSON file:

```bash
/var/ossec/integrations/custom-slack /var/ossec/logs/alerts/alerts.json
```

## Related Projects

- [Wazuh Telegram Integration](https://github.com/0xdolan/wazuh-telegram-integration) – Send Wazuh alerts to Telegram using a similar method.

## 🚀 Result

You’ll begin receiving real-time Slack alerts for all critical, high, and medium-level events. Each alert is detailed, well-formatted, and clearly marked by severity, helping you respond faster and more effectively.

If you found this useful or have questions, feel free to comment. Happy monitoring! 👨‍💻📱

---

_Created with ❤️ by [0xdolan](mailto:0xdolan@gmail.com)_

```

```
