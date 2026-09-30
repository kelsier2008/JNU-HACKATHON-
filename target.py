"""The monitored "target system": config.json plus the demo scenarios that change it.

- apply_hack()        attacker edits the file (no approval)       -> RED
- apply_dev_update()  developer ships a change (after approval)   -> BLUE
- restore_trusted()   roll the file back to the last anchored copy -> GREEN
"""
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parent
CONFIG_PATH = ROOT / "target_system" / "config.json"
STATE_DIR = ROOT / ".state"
SNAPSHOT_PATH = STATE_DIR / "trusted_config.json"  # copy of the last file whose hash went on-chain

BASELINE_CONFIG = {
    "service": "checkout-api",
    "version": "2.4.1",
    "environment": "production",
    "last_deployed": "2026-09-30T09:00:00Z",
    "payments": {
        "gateway_url": "https://payments.internal.example.com/v2",
        "currency": "USD",
        "max_transaction": 10000,
    },
    "auth": {
        "require_mfa": True,
        "session_timeout_min": 30,
        "admin_users": ["alice"],
    },
    "features": {
        "new_checkout_flow": False,
        "fraud_detection": True,
    },
    "logging": {
        "level": "INFO",
        "debug_mode": False,
    },
}


def read_config(path=CONFIG_PATH):
    return json.loads(Path(path).read_text())


def write_config(data, path=CONFIG_PATH):
    Path(path).write_text(json.dumps(data, indent=2) + "\n")


def write_baseline():
    write_config(BASELINE_CONFIG)


def save_snapshot():
    """Remember the exact bytes that were just anchored, so we can restore and diff."""
    STATE_DIR.mkdir(exist_ok=True)
    shutil.copyfile(CONFIG_PATH, SNAPSHOT_PATH)


def restore_trusted():
    """Self-heal: overwrite the live file with the last anchored copy."""
    if SNAPSHOT_PATH.exists():
        shutil.copyfile(SNAPSHOT_PATH, CONFIG_PATH)
    else:
        write_baseline()


def apply_hack():
    """Simulated attacker: redirect payments, weaken auth, plant a backdoor admin."""
    cfg = read_config()
    cfg["payments"]["gateway_url"] = "https://payments-verify.attacker.net/collect"
    cfg["auth"]["require_mfa"] = False
    if "backdoor" not in cfg["auth"]["admin_users"]:
        cfg["auth"]["admin_users"].append("backdoor")
    write_config(cfg)


def apply_dev_update():
    """Simulated developer release: bump patch version and flip a feature flag."""
    cfg = read_config()
    major, minor, patch = (int(x) for x in cfg["version"].split("."))
    cfg["version"] = f"{major}.{minor}.{patch + 1}"
    cfg["last_deployed"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cfg["features"]["new_checkout_flow"] = not cfg["features"]["new_checkout_flow"]
    write_config(cfg)


def _flatten(obj, prefix=""):
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            out.update(_flatten(v, f"{prefix}{k}."))
        return out
    return {prefix[:-1]: json.dumps(obj)}


def diff_vs_snapshot():
    """List of (key, old, new) between the last trusted copy and the live file."""
    try:
        old, new = _flatten(read_config(SNAPSHOT_PATH)), _flatten(read_config())
    except (OSError, ValueError):
        return []  # missing snapshot or live file isn't valid JSON anymore
    keys = sorted(set(old) | set(new))
    return [(k, old.get(k, "—"), new.get(k, "—")) for k in keys if old.get(k) != new.get(k)]
