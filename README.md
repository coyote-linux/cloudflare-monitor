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
