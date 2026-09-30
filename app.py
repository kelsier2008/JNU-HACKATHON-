"""Decentralized Runtime Integrity Engine: monitoring agent + live dashboard.

Every second the agent hashes config.json and compares it with the hash anchored
on-chain, then lands in exactly one of three states:

  VERIFIED               live hash == on-chain hash
  AUTHORIZED UPDATE      hashes differ, but the developer approved on-chain first
                         -> agent anchors the new hash (approval is consumed)
  UNAUTHORIZED MOD       hashes differ, no approval -> tamper alert written on-chain

Run:  streamlit run app.py
"""
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html import escape

import streamlit as st

import styles
import target
from hash_utils import sha256_file
from ledger import DEPLOYMENT_FILE, ChainOffline, Ledger, NotDeployed

POLL_SECONDS = 1.0        # how often the agent re-checks the file
BLUE_HOLD_SECONDS = 6     # keep the "Authorized update" banner visible after an anchor
MISSING = "file-missing"  # pseudo-hash when an attacker deletes the file outright

st.set_page_config(page_title="Runtime Integrity Engine", page_icon="🛡️",
                   layout="wide", initial_sidebar_state="auto")
st.markdown(styles.CSS, unsafe_allow_html=True)


# ------------------------------------------------------------------ shared resources
# st.cache_resource objects are shared by every browser tab, so two open dashboards
# can't both try to anchor the same hash at once.
@st.cache_resource
def engine_lock():
    return threading.Lock()


@st.cache_resource
def shared_state():
    return {"last_update_diff": []}


@st.cache_resource(show_spinner=False)
def _cached_ledger(deployment_stamp):
    return Ledger()


def get_ledger():
    """Return (ledger, None) or (None, "offline" | "undeployed")."""
    stamp = DEPLOYMENT_FILE.stat().st_mtime if DEPLOYMENT_FILE.exists() else 0
    try:
        return _cached_ledger(stamp), None
    except ChainOffline:
        return None, "offline"
    except NotDeployed:
        return None, "undeployed"
    except Exception:
        return None, "offline"


def live_hash():
    try:
        return sha256_file(target.CONFIG_PATH)
    except OSError:
        return MISSING


def utc(ts=None):
    return datetime.fromtimestamp(ts or time.time(), timezone.utc).strftime("%H:%M:%S")


def short(h):
    return h[:8] if h else "—"


# ----------------------------------------------------------------------- the engine
@dataclass
class Status:
    state: str                  # "verified" | "authorized" | "tamper"
    live: str
    trusted: str
    trail: list
    window_open: bool = False   # approval granted but file not changed yet
    event: object = None        # the trail entry that explains the state
    changes: list = field(default_factory=list)


def run_agent(ledger):
    """One monitoring cycle: hash, compare, act on-chain, classify."""
    with engine_lock():
        live, trusted = live_hash(), ledger.trusted_hash()

        if live != trusted:
            if ledger.update_authorized():
                # 🔵 Approved change: anchor the new fingerprint, consuming the approval.
                shared_state()["last_update_diff"] = target.diff_vs_snapshot()
                ledger.update_hash(live)
                target.save_snapshot()
                trusted = live
            else:
                # 🔴 Unapproved change: write the alert on-chain once per distinct bad hash.
                if not _already_reported(ledger.audit_trail(), live):
                    ledger.report_tamper(live)

        trail = ledger.audit_trail()

    if live != trusted:
        alert = next((e for e in reversed(trail) if e.kind == "tamper" and e.hash == live), None)
        return Status("tamper", live, trusted, trail, event=alert, changes=target.diff_vs_snapshot())

    last_anchor = next((e for e in reversed(trail) if e.kind == "anchored"), None)
    if last_anchor and last_anchor.by == ledger.agent and time.time() - last_anchor.timestamp < BLUE_HOLD_SECONDS:
        return Status("authorized", live, trusted, trail, event=last_anchor,
                      changes=shared_state()["last_update_diff"])
    return Status("verified", live, trusted, trail, window_open=ledger.update_authorized())


def _already_reported(trail, bad_hash):
    """Has this exact bad hash been reported since the last legitimate anchor?"""
    for e in reversed(trail):
        if e.kind == "anchored":
            return False
        if e.kind == "tamper" and e.hash == bad_hash:
            return True
    return False


# --------------------------------------------------------------------- HTML pieces
def html_header(online):
    live = (f'<div class="live"><span class="dot"></span>Live <span class="mono">{utc()}</span></div>'
            if online else '<div class="live off"><span class="dot"></span>Offline</div>')
    return ('<div class="topbar"><div><div class="title">Runtime integrity engine</div>'
            '<div class="subtitle">SHA-256 verification anchored on a blockchain</div></div>'
            f'{live}</div>')


def html_changes(changes, limit=4):
    rows = "".join(
        f'<div class="change"><span class="k">{escape(k)}</span> '
        f'<span class="old">{escape(old)}</span> → <span class="new">{escape(new)}</span></div>'
        for k, old, new in changes[:limit])
    return f'<div class="changes">{rows}</div>' if rows else ""


def html_status(s):
    if s.state == "verified":
        meta = f"Last check {utc()} UTC"
        if s.window_open:
            meta += " · update window open, waiting for the release"
        return _banner("s-verified", styles.ICON_VERIFIED, "Verified",
                       "All monitored files match the on-chain cryptographic reference.", meta)

    if s.state == "authorized":
        e = s.event
        return _banner("s-authorized", styles.ICON_AUTHORIZED, "Authorized update",
                       "Developer approval found on-chain. New fingerprint anchored; approval consumed.",
                       f"Anchored in block {e.block} at {utc(e.timestamp)} UTC by Agent-01",
                       html_changes(s.changes))

    e = s.event
    meta = (f"Tamper alert written on-chain in block {e.block} at {utc(e.timestamp)} UTC"
            if e else "Writing tamper alert on-chain…")
    msg = ("config.json was deleted. No update was authorized."
           if s.live == MISSING else
           "config.json no longer matches the on-chain reference, and no update was authorized.")
    return _banner("s-tamper", styles.ICON_TAMPER, "Unauthorized modification", msg, meta,
                   html_changes(s.changes))


def html_problem(problem):
    if problem == "undeployed":
        title, msg = "Contract not deployed", "The chain is up, but IntegrityLedger isn't deployed on it."
        cmd = ".venv/bin/python deploy.py"
    else:
        title, msg = "Blockchain offline", "Can't reach the local node at http://127.0.0.1:8545."
        cmd = "npx hardhat node<br>.venv/bin/python deploy.py"
    return _banner("s-offline", styles.ICON_OFFLINE, title, msg, "Retrying every second",
                   f'<div class="cmd">{cmd}</div>')


def _banner(cls, icon, title, msg, meta, extra=""):
    return (f'<div class="status {cls}">{icon}<div style="min-width:0">'
            f'<div class="status-title">{title}</div><div class="status-msg">{msg}</div>'
            f'<div class="status-meta">{meta}</div>{extra}</div></div>')


def _grouped(h, cls=""):
    if len(h) != 64:
        return f'<span class="{cls}">{escape(h)}</span>'
    return " ".join(f'<span class="{cls}">{h[i:i + 8]}</span>' for i in range(0, 64, 8))


def html_hashes(s):
    bad = "bad" if s.state == "tamper" else ""
    path = "./" + str(target.CONFIG_PATH.relative_to(target.ROOT))
    return (f'<div class="card"><div class="card-head"><span>Hash comparison</span>'
            f'<span class="mono">{path}</span></div>'
            f'<div class="hash-row"><div class="hash-label">Live file {short(s.live)}...</div>'
            f'<div class="hash">{_grouped(s.live, bad)}</div></div>'
            f'<div class="hash-row"><div class="hash-label">On-chain trusted {short(s.trusted)}...</div>'
            f'<div class="hash">{_grouped(s.trusted)}</div></div></div>')


_KIND = {"anchored": ("Anchored", "st-anchored"),
         "authorized": ("Approved", "st-authorized"),
         "tamper": ("Tamper detected", "st-tamper")}


def html_trail(s, ledger, max_blocks=4, max_rows=8):
    # Chain strip: the most recent blocks that carry integrity events (+ the deploy block).
    per_block = {ledger.deploy_block: ("Deploy", "")}
    for e in s.trail:
        label = {"anchored": short(e.hash), "authorized": "Approval", "tamper": "⚠ " + short(e.hash)}[e.kind]
        per_block[e.block] = (label, e.kind)
    recent = sorted(per_block.items())[-max_blocks:]
    cards = f'<div class="chain-link">{styles.ICON_LINK}</div>'.join(
        f'<div class="blk {kind}"><div class="blk-n">Block {n}</div><div class="blk-v">{label}</div></div>'
        for n, (label, kind) in recent)

    rows = "".join(
        f'<tr><td class="mono">{utc(e.timestamp)}</td>'
        f'<td class="mono">{short(e.hash) if e.hash else "—"}</td>'
        f'<td class="{_KIND[e.kind][1]}">{_KIND[e.kind][0]}</td>'
        f'<td>{ledger.label(e.by)}</td></tr>'
        for e in list(reversed(s.trail))[:max_rows])

    addr = f"{ledger.address[:10]}...{ledger.address[-4:]}"
    return (f'<div class="card"><div class="card-head"><span>Blockchain audit trail</span>'
            f'<span class="mono">{addr}</span></div><div class="blocks">{cards}</div>'
            '<div class="table-wrap"><table class="trail"><thead><tr><th>Time (UTC)</th><th>Hash</th>'
            f'<th>Status</th><th>By</th></tr></thead><tbody>{rows}</tbody></table></div></div>')


# ------------------------------------------------------------------ sidebar: demo panel
ledger, problem = get_ledger()

with st.sidebar:
    st.html('<div class="side-title">Demo panel</div><div class="side-sub">Try the attack live</div>')
    hack = st.button("Simulate hack", icon=":material/skull:", key="btn_hack", width="stretch")
    approve = st.button("Approve update", icon=":material/signature:", key="btn_approve", width="stretch")
    reset = st.button("Reset", icon=":material/refresh:", key="btn_reset", width="stretch")

if hack:
    target.apply_hack()
    st.toast("Attacker rewrote config.json", icon=":material/skull:")

if approve:
    if ledger is None:
        st.toast("Blockchain offline", icon=":material/cloud_off:")
    elif live_hash() != ledger.trusted_hash() and not ledger.update_authorized():
        # Approval must come BEFORE the change: signing off on an already-tampered file
        # would launder the attack into the trusted state.
        st.toast("Blocked: the file is already tampered. Reset first — approvals can't be applied retroactively.",
                 icon=":material/block:")
    else:
        ledger.authorize_update()     # developer key opens a one-shot window on-chain
        target.apply_dev_update()     # ...then the release lands on disk
        st.toast("Developer approved on-chain, release v" + target.read_config()["version"] + " applied",
                 icon=":material/signature:")

if reset:
    target.restore_trusted()
    st.toast("config.json restored from the last trusted snapshot", icon=":material/refresh:")

with st.sidebar:
    chain = f"Hardhat, chain {ledger.chain_id}" if ledger else "Hardhat, offline"
    st.html(f'<div class="side-info">Agent-01 (Production)<br>{target.CONFIG_PATH.name}<br>{chain}</div>')


# ------------------------------------------------------------- main: live dashboard
@st.fragment(run_every=POLL_SECONDS)
def dashboard():
    ledger, problem = get_ledger()
    status = None
    if ledger:
        try:
            status = run_agent(ledger)
        except Exception:
            _cached_ledger.clear()  # node restarted or contract gone: reconnect next tick
            problem = "offline"

    st.html(html_header(online=status is not None))
    if status is None:
        st.html(html_problem(problem))
        return
    st.html(html_status(status))
    st.html(html_hashes(status))
    st.html(html_trail(status, ledger))


dashboard()
