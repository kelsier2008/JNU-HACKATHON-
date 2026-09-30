"""Web3.py bridge to the IntegrityLedger contract on the local Hardhat chain."""
import json
import os
import warnings
from dataclasses import dataclass
from pathlib import Path

warnings.filterwarnings("ignore", message="urllib3 v2 only supports OpenSSL")  # macOS system Python

from web3 import Web3

ROOT = Path(__file__).parent
DEPLOYMENT_FILE = ROOT / "deployment.json"  # written by deploy.py
RPC_URL = os.environ.get("RPC_URL", "http://127.0.0.1:8545")


class ChainOffline(Exception):
    pass


class NotDeployed(Exception):
    pass


@dataclass
class TrailEntry:
    kind: str       # "authorized" | "anchored" | "tamper"
    block: int
    log_index: int
    timestamp: int
    hash: str       # "" for authorizations
    by: str         # sender address


class Ledger:
    def __init__(self, rpc_url=RPC_URL):
        self.w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 3}))
        if not self.w3.is_connected():
            raise ChainOffline(rpc_url)
        if not DEPLOYMENT_FILE.exists():
            raise NotDeployed("deployment.json missing")

        dep = json.loads(DEPLOYMENT_FILE.read_text())
        # A restarted Hardhat node forgets everything: detect a stale deployment.json.
        if len(self.w3.eth.get_code(dep["address"])) == 0:
            raise NotDeployed("no contract code at " + dep["address"])

        self.address = dep["address"]
        self.contract = self.w3.eth.contract(address=dep["address"], abi=dep["abi"])
        self.dev = dep["dev"]          # owner: the only key that can approve updates
        self.agent = dep["agent"]      # monitoring agent: commits hashes, reports tampering
        self.deploy_block = dep["deployBlock"]
        self.chain_id = self.w3.eth.chain_id

    # ------------------------------------------------------------------ reads
    def trusted_hash(self):
        return self.contract.functions.getTrustedHash().call()

    def update_authorized(self):
        return self.contract.functions.isUpdateAuthorized().call()

    def block_number(self):
        return self.w3.eth.block_number

    # ----------------------------------------------------------------- writes
    def _send(self, fn, sender):
        tx = fn.transact({"from": sender})  # Hardhat node accounts are unlocked
        return self.w3.eth.wait_for_transaction_receipt(tx, timeout=10)

    def authorize_update(self):
        return self._send(self.contract.functions.authorizeUpdate(), self.dev)

    def update_hash(self, new_hash):
        return self._send(self.contract.functions.updateHash(new_hash), self.agent)

    def report_tamper(self, observed_hash):
        return self._send(self.contract.functions.reportTamper(observed_hash), self.agent)

    # ------------------------------------------------------------ audit trail
    def audit_trail(self):
        """Every contract event since deployment, oldest first."""
        events = self.contract.events
        sources = (
            ("authorized", events.UpdateAuthorized, lambda a: ""),
            ("anchored", events.HashAnchored, lambda a: a["newHash"]),
            ("tamper", events.TamperDetected, lambda a: a["observedHash"]),
        )
        trail = []
        for kind, event, get_hash in sources:
            for log in event.get_logs(from_block=self.deploy_block):
                a = log["args"]
                trail.append(TrailEntry(
                    kind=kind,
                    block=log["blockNumber"],
                    log_index=log["logIndex"],
                    timestamp=a["timestamp"],
                    hash=get_hash(a),
                    by=a.get("by") or a.get("reporter"),
                ))
        trail.sort(key=lambda e: (e.block, e.log_index))
        return trail

    def label(self, address):
        return {self.dev: "Dev", self.agent: "Agent-01"}.get(address, address[:8] + "…")
