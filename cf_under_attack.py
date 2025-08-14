#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
import urllib.error

CONFIG_PATH = os.environ.get("CF_GUARD_CONFIG", "/etc/cf-under-attack.conf")

def load_config(path):
    """
    Load simple KEY=VALUE lines from the existing conf file.
    Supports quoted values; ignores comments and blank lines.
    """
    cfg = {}
    if not os.path.isfile(path):
        print(f"Config file not found: {path}", file=sys.stderr)
        sys.exit(1)

    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # allow inline comments when not inside quotes
            if "#" in line and not re.search(r'(?<!\\)"', line):  # crude but fine
                line = line.split("#", 1)[0].strip()
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip()
            # remove surrounding quotes if present
            if v.startswith(("'", '"')) and v.endswith(("'", '"')):
                v = v[1:-1]
            cfg[k] = v
    return cfg

def cfg_get(cfg, key, default=None, cast=None):
    v = cfg.get(key, default)
    if cast and v is not None:
        try:
            return cast(v)
        except Exception:
            return default
    return v

def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

# --------------------------
# Load / Guard state helpers
# --------------------------
def read_5min_load():
    # /proc/loadavg: 1m 5m 15m ...
    try:
        with open("/proc/loadavg", "r", encoding="utf-8") as f:
            parts = f.read().split()
            return float(parts[1])  # 5-minute average
    except Exception:
        return 0.0

def read_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return ""

def write_file(path, content):
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return True
    except Exception:
        return False

def remove_file(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    except Exception:
        pass

# --------------------------
# Cloudflare API
# --------------------------
def cf_request(method, url, token, data=None, timeout=15):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "cf-guard/1.0",
    }
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8") or "{}")
        except Exception:
            return e.code, {"success": False, "error": str(e)}
    except Exception as e:
        return 0, {"success": False, "error": str(e)}

def cf_get_mode(zone_id, token):
    code, payload = cf_request(
        "GET",
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/security_level",
        token,
    )
    if code == 200:
        # payload like: {"success":true,"result":{"id":"security_level","value":"medium",...}}
        try:
            return payload.get("result", {}).get("value", "")
        except Exception:
            return ""
    return ""

def cf_set_mode(zone_id, token, value):
    code, payload = cf_request(
        "PATCH",
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/security_level",
        token,
        data={"value": value},
    )
    success = bool(payload.get("success")) if isinstance(payload, dict) else False
    return code, success, payload

# --------------------------
# Alerts (slack/email/command)
# --------------------------
def which(cmd):
    return shutil.which(cmd) is not None

def can_alert(ts_file, cooldown_min):
    if not ts_file:
        return True
    try:
        last = int(read_file(ts_file) or "0")
    except Exception:
        last = 0
    now = int(time.time())
    return (now - last) >= int(cooldown_min * 60)

def record_alert_ts(ts_file):
    if ts_file:
        write_file(ts_file, str(int(time.time())))

def alert_slack(webhook, msg, use_blocks, host, target_mode, load_now, threshold):
    if not webhook:
        return
    if use_blocks:
        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": "Cloudflare Guard Alert", "emoji": True},
                },
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*{msg}*"}},
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Host:*\n{host}"},
                        {"type": "mrkdwn", "text": f"*Time (UTC):*\n{now_iso()}"},
                        {"type": "mrkdwn", "text": f"*Target Mode:*\n{target_mode}"},
                        {"type": "mrkdwn", "text": f"*Load / Threshold:*\n{load_now} / {threshold}"},
                    ],
                },
                {"type": "context", "elements": [{"type": "mrkdwn", "text": "Automated by cf-guard"}]},
            ]
        }
    else:
        payload = {"text": msg}
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(webhook, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as _:
            pass
    except Exception:
        pass

def alert_email(to_addr, from_addr, subject_prefix, msg):
    # Prefer sendmail if available; otherwise try localhost SMTP via /usr/sbin/sendmail fallback logic
    subject = f"{subject_prefix or '[CF Guard]'} Notification"
    body = f"From: {from_addr}\nTo: {to_addr}\nSubject: {subject}\nContent-Type: text/plain; charset=UTF-8\n\n{msg}\n"
    try:
        if which("sendmail"):
            p = subprocess.Popen(["sendmail", "-t"], stdin=subprocess.PIPE)
            p.communicate(body.encode("utf-8"), timeout=10)
            return
        elif which("mail"):
            p = subprocess.Popen(["mail", "-a", f"From:{from_addr}", "-s", subject, to_addr], stdin=subprocess.PIPE)
            p.communicate(msg.encode("utf-8"), timeout=10)
            return
    except Exception:
        pass  # stay silent like the shell script

def alert_command(command_tpl, msg):
    if not command_tpl:
        return
    try:
        if "#MSG#" in command_tpl:
            cmd = command_tpl.replace("#MSG#", shlex.quote(msg))
        else:
            cmd = f"{command_tpl} {shlex.quote(msg)}"
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    except Exception:
        pass

def send_alert(cfg, msg, host, target_mode, load_now, threshold):
    mode = cfg_get(cfg, "ALERT_MODE", "none").lower()
    if mode == "none":
        return
    ts_file = cfg_get(cfg, "ALERT_TS_FILE", "/tmp/cf_under_attack_alert_ts")
    cooldown = cfg_get(cfg, "ALERT_COOLDOWN_MIN", 30, float)

    if not can_alert(ts_file, cooldown):
        return

    if mode == "slack":
        webhook = cfg_get(cfg, "ALERT_SLACK_WEBHOOK", "")
        use_blocks = str(cfg_get(cfg, "ALERT_SLACK_USE_BLOCKS", "true")).lower() == "true"
        alert_slack(webhook, msg, use_blocks, host, target_mode, load_now, threshold)
    elif mode == "email":
        to_addr = cfg_get(cfg, "ALERT_EMAIL_TO", "")
        from_addr = cfg_get(cfg, "ALERT_EMAIL_FROM", f"cf-guard@{socket.gethostname()}")
        subj_prefix = cfg_get(cfg, "ALERT_EMAIL_SUBJECT_PREFIX", "[CF Guard]")
        if to_addr:
            alert_email(to_addr, from_addr, subj_prefix, msg)
    elif mode == "command":
        command = cfg_get(cfg, "ALERT_COMMAND", "")
        alert_command(command, msg)

    record_alert_ts(ts_file)

# --------------------------
# Main flow
# --------------------------
def main():
    cfg = load_config(CONFIG_PATH)

    # Required config
    zone_id = cfg_get(cfg, "ZONE_ID")
    token = cfg_get(cfg, "CF_API_TOKEN")
    if not zone_id or not token:
        print("Missing ZONE_ID or CF_API_TOKEN in config.", file=sys.stderr)
        return 1

    # Operational config
    load_threshold = cfg_get(cfg, "LOAD_THRESHOLD", 7.0, float)
    low_load_mode = cfg_get(cfg, "LOW_LOAD_MODE", "medium")
    cache_file = cfg_get(cfg, "CACHE_FILE", "/tmp/cf_mode_cache")
    ts_file = cfg_get(cfg, "TIMESTAMP_FILE", "/tmp/cf_under_attack_timestamp")
    cooldown_hours = cfg_get(cfg, "COOLDOWN_HOURS", 3, float)

    # State
    host = socket.gethostname()
    load_now = round(read_5min_load(), 2)
    threshold = round(float(load_threshold), 2)

    # Cloudflare actual mode
    actual_mode = cf_get_mode(zone_id, token)
    if not actual_mode:
        print("Failed to retrieve current Cloudflare mode.", file=sys.stderr)
        return 2

    # Cached mode
    last_mode = read_file(cache_file) or ""

    # Manual override detection & cache sync
    if actual_mode != last_mode:
        print(f"Syncing cache. Cloudflare mode changed manually from '{last_mode}' to '{actual_mode}'.")
        write_file(cache_file, actual_mode)
        last_mode = actual_mode
        if actual_mode == "under_attack":
            write_file(ts_file, str(int(time.time())))
            send_alert(cfg, f"{host}: CF mode set to UNDER ATTACK manually at {now_iso()}",
                       host, actual_mode, load_now, threshold)
        else:
            remove_file(ts_file)
            send_alert(cfg, f"{host}: CF mode set to '{actual_mode}' manually at {now_iso()}",
                       host, actual_mode, load_now, threshold)

    # Determine target mode (same logic as your shell)
    target_mode = low_load_mode
    if load_now > threshold:
        target_mode = "under_attack"
        if last_mode != "under_attack":
            write_file(ts_file, str(int(time.time())))
    elif last_mode == "under_attack" and os.path.isfile(ts_file):
        try:
            activated_at = int(read_file(ts_file) or "0")
        except Exception:
            activated_at = 0
        elapsed = int(time.time()) - activated_at
        cooldown_seconds = int(cooldown_hours * 3600)
        if elapsed < cooldown_seconds:
            target_mode = "under_attack"
        else:
            remove_file(ts_file)

    # Apply mode change if needed
    if target_mode != last_mode:
        print(f"Setting Cloudflare security level to: {target_mode}")
        code, success, _ = cf_set_mode(zone_id, token, target_mode)
        if success:
            write_file(cache_file, target_mode)
            if target_mode == "under_attack":
                send_alert(cfg, f"{host}: ENTERED UNDER ATTACK (load={load_now}, threshold={threshold}) at {now_iso()}",
                           host, target_mode, load_now, threshold)
            else:
                send_alert(cfg, f"{host}: EXITED UNDER ATTACK → '{target_mode}' (load={load_now}) at {now_iso()}",
                           host, target_mode, load_now, threshold)
        else:
            print(f"Cloudflare API failed with HTTP {code}.", file=sys.stderr)

    return 0

if __name__ == "__main__":
    sys.exit(main())
