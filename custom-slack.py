#!/var/ossec/venv/bin/python

import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

import requests

# ---------------------------
# Configuration
# ---------------------------

ALERT_FILE = "/var/ossec/logs/alerts/alerts.json"
OFFSET_FILE = "/var/ossec/integrations/last_offset.txt"

# Only process alerts newer than this many hours when offset file is missing/reset
MAX_ALERT_AGE_HOURS = 24

# Slack webhook URLs (Critical, High, Medium, Low)
WEBHOOK_CRITICAL = ""  # replace with your Critical channel webhook
WEBHOOK_HIGH = ""  # replace with your High channel webhook
WEBHOOK_MEDIUM = ""  # replace with your Medium channel webhook
WEBHOOK_LOW = ""  # replace with your Low channel webhook

# Excluded Wazuh Rule IDs - Example: ["1002", "5715", "18107"]
EXCLUDED_RULES: list = []

# ---------------------------
# Utility Functions
# ---------------------------


def escape_markdown(text):
    """Escape Slack markdown characters (*, _, `, ~)."""
    if not isinstance(text, str):
        text = str(text)
    return re.sub(r"([*`_~])", r"\\\1", text)


def choose_webhook(level):
    try:
        lvl = int(level)
    except (ValueError, TypeError):
        return None

    if lvl >= 15:
        return WEBHOOK_CRITICAL
    elif 12 <= lvl <= 14:
        return WEBHOOK_HIGH
    elif 7 <= lvl <= 11:
        return WEBHOOK_MEDIUM
    elif 0 <= lvl <= 6:
        return WEBHOOK_LOW
    else:
        return None


def parse_alert_timestamp(timestamp_raw):
    """Parse alert timestamp from various formats and return datetime object.

    Returns:
        datetime object if parsing succeeds, None otherwise
    """
    if not timestamp_raw or timestamp_raw == "unknown":
        return None

    try:
        # Handle ISO format with Z timezone
        if timestamp_raw.endswith("Z"):
            dt = datetime.fromisoformat(timestamp_raw.replace("Z", "+00:00"))
        # Handle ISO format with timezone offset (e.g., -0800, +00:00)
        elif "+" in timestamp_raw or (
            timestamp_raw.count("-") > 2 and len(timestamp_raw) > 19
        ):
            # Try parsing as-is (handles formats like "2025-12-18T00:00:00.950-0800")
            dt = datetime.fromisoformat(timestamp_raw)
        else:
            # Try parsing without timezone info
            dt = datetime.fromisoformat(timestamp_raw)
            # Assume UTC if no timezone info
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, AttributeError) as e:
        print(f"[WARN] Failed to parse timestamp '{timestamp_raw}': {e}")
        return None


def is_alert_too_old(alert_dt, max_age_hours=MAX_ALERT_AGE_HOURS):
    """Check if alert is older than the maximum age threshold.

    Returns:
        True if alert is too old, False otherwise
    """
    if alert_dt is None:
        return False  # If we can't parse timestamp, process it anyway

    # Normalize both to UTC for comparison
    if alert_dt.tzinfo:
        alert_utc = alert_dt.astimezone(timezone.utc)
    else:
        # Assume UTC if no timezone info
        alert_utc = alert_dt.replace(tzinfo=timezone.utc)

    now_utc = datetime.now(timezone.utc)
    age = now_utc - alert_utc
    return age > timedelta(hours=max_age_hours)


def process_alert(alert, skip_old_alerts=False):
    """Process a single alert and send to Slack if applicable.

    Args:
        alert: Alert JSON object
        skip_old_alerts: If True, skip alerts older than MAX_ALERT_AGE_HOURS
    """
    rule_id = alert.get("rule", {}).get("id")
    if rule_id in EXCLUDED_RULES:
        return

    # Check alert age if requested
    timestamp_raw = alert.get("timestamp")
    alert_dt = parse_alert_timestamp(timestamp_raw)
    if skip_old_alerts and is_alert_too_old(alert_dt):
        print(f"[INFO] Skipping old alert from {timestamp_raw}")
        return

    data = alert.get("data", {})
    srcuser = data.get("srcuser") or data.get("dstuser") or "unknown"
    srcip = data.get("srcip", "unknown")
    srcport = data.get("srcport", "unknown")
    agent_name = alert.get("agent", {}).get("name", "unknown")
    alert_level = alert.get("rule", {}).get("level", "unknown")
    description = alert.get("rule", {}).get("description", "No description")
    full_log = alert.get("full_log", "No full log available")

    # Format timestamp for display - use alert timestamp, not current time
    if alert_dt:
        # Convert to local timezone for display
        if alert_dt.tzinfo:
            timestamp = alert_dt.strftime("%Y-%m-%d %H:%M:%S %Z")
        else:
            timestamp = alert_dt.strftime("%Y-%m-%d %H:%M:%S")
    else:
        # Fallback to raw timestamp if parsing failed
        timestamp = timestamp_raw if timestamp_raw else "unknown"

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

    text += "\n\n────────────────────────\n"

    webhook_url = choose_webhook(alert_level)
    if not webhook_url:
        print(f"[INFO] Skipping alert with level {alert_level} — no webhook defined.")
        return

    try:
        resp = requests.post(webhook_url, json={"text": text})
        if resp.status_code != 200:
            print(f"[ERROR] Slack response: {resp.status_code} – {resp.text}")
    except requests.RequestException as e:
        print(f"[ERROR] Failed to send alert to Slack: {e}")


# ---------------------------
# Main
# ---------------------------


def process_single_alert_file(alert_file_path):
    """Process a single alert file (standard Wazuh integration mode).

    This is called when Wazuh passes an alert file path as an argument.
    """
    try:
        with open(alert_file_path, "r") as f:
            alert = json.load(f)
            process_alert(alert, skip_old_alerts=False)
            print(f"[INFO] Processed alert from {alert_file_path}")
    except FileNotFoundError:
        print(f"[ERROR] Alert file not found: {alert_file_path}")
    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid JSON in alert file {alert_file_path}: {e}")
    except Exception as e:
        print(f"[ERROR] Error processing alert file {alert_file_path}: {e}")


def process_alerts_json_file():
    """Process alerts from the continuous alerts.json log file.

    This mode is used when the script is run without arguments (e.g., as a daemon/cron).
    It reads from /var/ossec/logs/alerts/alerts.json using offset tracking.
    """
    last_offset = 0
    offset_file_exists = os.path.exists(OFFSET_FILE)
    skip_old_alerts = False

    # Read last processed offset
    if offset_file_exists:
        with open(OFFSET_FILE, "r") as f:
            try:
                last_offset = int(f.read().strip())
                print(f"[INFO] Resuming from offset: {last_offset}")
            except ValueError:
                print(
                    f"[WARN] Invalid offset file, starting from beginning (will skip old alerts)"
                )
                last_offset = 0
                skip_old_alerts = True
    else:
        # Offset file doesn't exist - this is likely first run or after reset
        # To avoid sending all historical alerts, we'll skip old ones
        print(
            f"[INFO] Offset file not found. Starting from beginning but skipping alerts older than {MAX_ALERT_AGE_HOURS} hours"
        )
        skip_old_alerts = True
        last_offset = 0

    # Read new alerts from alerts.json
    if not os.path.exists(ALERT_FILE):
        print(f"[ERROR] Alert file {ALERT_FILE} does not exist")
        return

    alerts_processed = 0
    alerts_skipped_old = 0
    alerts_skipped_other = 0

    try:
        with open(ALERT_FILE, "r") as f:
            # If offset file didn't exist, we might want to start from a recent position
            # But for now, we'll start from beginning and filter by age
            if last_offset > 0:
                f.seek(last_offset)

            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    alert = json.loads(line)
                    # Check if we should skip this alert due to age
                    timestamp_raw = alert.get("timestamp")
                    alert_dt = parse_alert_timestamp(timestamp_raw)

                    if skip_old_alerts and is_alert_too_old(alert_dt):
                        alerts_skipped_old += 1
                        continue

                    process_alert(
                        alert, skip_old_alerts=False
                    )  # Already filtered above
                    alerts_processed += 1
                except json.JSONDecodeError as e:
                    print(f"[WARN] Skipping invalid JSON line: {e}")
                    alerts_skipped_other += 1
                except Exception as e:
                    print(f"[ERROR] Error processing alert: {e}")
                    alerts_skipped_other += 1

            # Save new offset
            new_offset = f.tell()
            with open(OFFSET_FILE, "w") as f_offset:
                f_offset.write(str(new_offset))

            print(
                f"[INFO] Processed {alerts_processed} alerts, skipped {alerts_skipped_old} old alerts, {alerts_skipped_other} errors. New offset: {new_offset}"
            )

    except Exception as e:
        print(f"[ERROR] Fatal error reading alerts file: {e}")
        raise


def main():
    """Main entry point. Handles both Wazuh integration mode and batch processing mode.

    - If called with arguments (standard Wazuh integration): args[1] = alert file path
    - If called without arguments: reads from alerts.json log file
    """
    # Check if called by Wazuh with alert file path as argument
    if len(sys.argv) > 1:
        # Standard Wazuh integration mode: process single alert file
        alert_file_path = sys.argv[1]
        process_single_alert_file(alert_file_path)
    else:
        # Batch processing mode: read from alerts.json log file
        process_alerts_json_file()


if __name__ == "__main__":
    main()
