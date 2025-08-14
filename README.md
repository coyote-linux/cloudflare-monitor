# Cloudflare Under Attack Mode Auto-Trigger (Python)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Automatically monitor Linux server load and toggle [Cloudflare's "Under Attack Mode"](https://developers.cloudflare.com/ddos-protection/) using their API when CPU load spikes above a configurable threshold.  

This tool is ideal for mitigating sudden traffic surges or DDoS attacks by enabling Cloudflare’s extra protection layer **within seconds** — without waiting for manual intervention.

Repo URL: **https://github.com/coyote-linux/cloudflare-monitor**

---

## Features

- **Automatic load monitoring** using the 5-minute system load average
- **Cloudflare API integration** for instant security level changes
- **Configurable cooldown** to avoid rapid toggling
- **Respects manual overrides** in the Cloudflare dashboard
- **Optional alerts** via:
  - Slack (plain text or Block Kit)
  - Email
  - Custom shell command
- **Secure config file** with no secrets in the script
- **Two deployment modes**:
  - Long-running `systemd` service
  - Periodic `systemd` timer (oneshot)

---

## Requirements

- Python **3.6+**
- `sendmail` or `mail` (if using email alerts)
- Linux system with `/proc/loadavg` available
- Cloudflare API Token with **Zone:Edit** permission for `settings/security_level`

---

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/coyote-linux/cloudflare-monitor.git
cd cloudflare-monitor
```

### 2. Install the script
```bash
sudo mkdir -p /opt/cloudflare-monitor
sudo cp cf_under_attack.py /opt/cloudflare-monitor/
sudo chmod +x /opt/cloudflare-monitor/cf_under_attack.py
```

### 3. Create and configure /etc/cf-under-attack.conf
```bash
sudo cp cf-under-attack.conf.example /etc/cf-under-attack.conf
sudo chmod 600 /etc/cf-under-attack.conf
sudo nano /etc/cf-under-attack.conf
```

Configuration file (/etc/cf-under-attack.conf):
```bash
LOAD_THRESHOLD=7.00
CF_API_TOKEN="PUT_CF_API_TOKEN_HERE"
ZONE_ID="PUT_CF_ZONE_ID_HERE"
LOW_LOAD_MODE="medium"
COOLDOWN_HOURS=3
CACHE_FILE="/tmp/cf_mode_cache"
TIMESTAMP_FILE="/tmp/cf_under_attack_timestamp"

# Alerts
ALERT_MODE="slack"  # none|slack|email|command
ALERT_SLACK_WEBHOOK="https://hooks.slack.com/services/XXX/YYY/ZZZ"
ALERT_SLACK_USE_BLOCKS=true
ALERT_EMAIL_TO="alerts@example.com"
ALERT_EMAIL_FROM="cf-guard@example.com"
ALERT_EMAIL_SUBJECT_PREFIX="[CF Guard]"
ALERT_COMMAND=""
ALERT_COOLDOWN_MIN=30
ALERT_TS_FILE="/tmp/cf_under_attack_alert_ts"
```

Fill in:

CF_API_TOKEN (Cloudflare API Token)
ZONE_ID (Cloudflare Zone ID)
Thresholds, cooldowns, and alert settings

## Deployment

### Option 1 - Long-Running Service
```bash
sudo cp systemd/cf-under-attack.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cf-under-attack.service
```

### Option 2 - systemd Timer (Oneshot Runs)
```bash
sudo cp systemd/cf-under-attack.timer /etc/systemd/system/
sudo cp systemd/cf-under-attack.timer.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cf-under-attack.timer
```

## Alerts

### Slack
- Set ALERT_MODE=slack and ALERT_SLACK_WEBHOOK
- Set ALERT_SLACK_USE_BLOCKS=true for rich Slack Block Kit messages

### Email
- Set ALERT_MODE=command and ALERT_COMMAND to any shell command
- Use #MSG# in the command to substitute the alert message

### Custom Command
- Set ALERT_MODE=command and ALERT_COMMAND to any shell command
- Use #MSG# in the command to substitute the alert message

## Testing
Run manually:
```bash
sudo /opt/cloudflare-monitor/cf_under_attack.py
```

