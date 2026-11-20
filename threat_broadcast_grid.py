from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import base64
import hashlib
import hmac
import json
import os
from typing import Callable, Dict, List, Set

SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


@dataclass
class ThreatIndicator:
    indicator_id: str
    observed_at: str
    source_sector: str
    threat_category: str
    ioc_type: str
    ioc_hash: str
    severity: str
    confidence: float


def _derive_keystream(secret: bytes, nonce: bytes, length: int) -> bytes:
    """Derive a keystream of exact byte length using HMAC-SHA256 counter blocks."""
    blocks = bytearray()
    counter = 0
    while len(blocks) < length:
        msg = nonce + counter.to_bytes(4, "big")
        block = hmac.new(secret, msg, hashlib.sha256).digest()
        blocks.extend(block)
        counter += 1
    return bytes(blocks[:length])


def _xor_bytes(data: bytes, keystream: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, keystream))


class StandardLibBroadcastGrid:
    def __init__(self, shared_secret: str, max_age_seconds: int = 300):
        self._secret = shared_secret.encode("utf-8")
        self._max_age_seconds = max_age_seconds
        self._seen_indicators: Set[str] = set()
        self._subscribers: Dict[str, List[dict]] = {}

    def subscribe(
        self,
        topic: str,
        org_name: str,
        min_severity: str,
        callback: Callable[[dict, str], None],
    ) -> None:
        normalized_severity = min_severity.upper()
        if normalized_severity not in SEVERITY_RANK:
            raise ValueError(f"Unsupported severity level: {min_severity}")

        entry = {
            "org_name": org_name,
            "min_rank": SEVERITY_RANK[normalized_severity],
            "callback": callback,
        }
        self._subscribers.setdefault(topic, []).append(entry)

    def _sign_envelope_parts(self, topic: str, published_at: str, nonce_b64: str, cipher_b64: str) -> str:
        canonical = f"{topic}|{published_at}|{nonce_b64}|{cipher_b64}".encode("utf-8")
        return hmac.new(self._secret, canonical, hashlib.sha256).hexdigest()

    def verify_envelope(self, envelope: dict) -> bool:
        expected_sig = self._sign_envelope_parts(
            envelope["topic"],
            envelope["published_at"],
            envelope["nonce"],
            envelope["ciphertext"],
        )
        return hmac.compare_digest(expected_sig, envelope["hmac_signature"])

    def _is_fresh(self, published_at_iso: str) -> bool:
        published_dt = datetime.fromisoformat(published_at_iso)
        age_seconds = (datetime.now(timezone.utc) - published_dt).total_seconds()
        return 0 <= age_seconds <= self._max_age_seconds

    def decrypt_payload(self, envelope: dict) -> dict:
        nonce = base64.b64decode(envelope["nonce"].encode("ascii"))
        ciphertext = base64.b64decode(envelope["ciphertext"].encode("ascii"))
        keystream = _derive_keystream(self._secret, nonce, len(ciphertext))
        plaintext = _xor_bytes(ciphertext, keystream)
        return json.loads(plaintext.decode("utf-8"))

    def deliver_envelope(self, envelope: dict) -> None:
        topic = envelope["topic"]

        if not self._is_fresh(envelope["published_at"]):
            print(f"[DROPPED] Stale envelope on topic '{topic}'")
            return

        for sub in self._subscribers.get(topic, []):
            org_name = sub["org_name"]
            if not self.verify_envelope(envelope):
                print(f"[REJECTED] Signature check failed for {org_name} on '{topic}'")
                continue

            data = self.decrypt_payload(envelope)
            msg_rank = SEVERITY_RANK.get(data["severity"].upper(), 1)
            if msg_rank >= sub["min_rank"]:
                sub["callback"](data, topic)

    def publish(self, topic: str, indicator: ThreatIndicator) -> dict | None:
        dedup_key = f"{topic}:{indicator.ioc_hash}:{indicator.threat_category}"
        if dedup_key in self._seen_indicators:
            print(f"[SKIPPED] Duplicate indicator {indicator.indicator_id} on '{topic}'")
            return None

        self._seen_indicators.add(dedup_key)

        plaintext = json.dumps(asdict(indicator), sort_keys=True).encode("utf-8")
        nonce = os.urandom(16)
        keystream = _derive_keystream(self._secret, nonce, len(plaintext))
        ciphertext = _xor_bytes(plaintext, keystream)

        published_at = datetime.now(timezone.utc).isoformat()
        nonce_b64 = base64.b64encode(nonce).decode("ascii")
        cipher_b64 = base64.b64encode(ciphertext).decode("ascii")

        envelope = {
            "topic": topic,
            "published_at": published_at,
            "nonce": nonce_b64,
            "ciphertext": cipher_b64,
            "hmac_signature": self._sign_envelope_parts(topic, published_at, nonce_b64, cipher_b64),
        }

        self.deliver_envelope(envelope)
        return envelope


def build_subscriber_handler(org_name: str) -> Callable[[dict, str], None]:
    def handle_alert(indicator_data: dict, topic: str) -> None:
        print(
            f"[{org_name}] [{topic}] {indicator_data['threat_category']} "
            f"| Severity={indicator_data['severity']} "
            f"| Confidence={indicator_data['confidence']:.2f} "
            f"| {indicator_data['ioc_type']}={indicator_data['ioc_hash'][:14]}... "
            f"| Source={indicator_data['source_sector']}"
        )

    return handle_alert


def run_grid_demo() -> None:
    grid = StandardLibBroadcastGrid(
        shared_secret="cross-industry-grid-secret-2026",
        max_age_seconds=120,
    )

    grid.subscribe(
        "financial-fraud",
        "Commercial-Bank-Node",
        "HIGH",
        build_subscriber_handler("Commercial-Bank-Node"),
    )
    grid.subscribe(
        "financial-fraud",
        "Payment-Gateway-Node",
        "MEDIUM",
        build_subscriber_handler("Payment-Gateway-Node"),
    )
    grid.subscribe(
        "retail-pos-security",
        "Retail-Network-Node",
        "HIGH",
        build_subscriber_handler("Retail-Network-Node"),
    )

    now_iso = datetime.now(timezone.utc).isoformat()
    sample_ioc_hash = hashlib.sha256(b"198.51.100.42").hexdigest()

    high_indicator = ThreatIndicator(
        indicator_id="IND-2026-9001",
        observed_at=now_iso,
        source_sector="Banking",
        threat_category="CREDENTIAL_STUFFING_BOTNET",
        ioc_type="ipv4_hash",
        ioc_hash=sample_ioc_hash,
        severity="HIGH",
        confidence=0.94,
    )

    print("--- Publishing valid HIGH indicator ---")
    valid_envelope = grid.publish("financial-fraud", high_indicator)

    print("\n--- Publishing duplicate indicator (should be skipped) ---")
    grid.publish("financial-fraud", high_indicator)

    if valid_envelope:
        print("\n--- Simulating tampered ciphertext on delivery (should be rejected) ---")
        tampered_envelope = dict(valid_envelope)
        tampered_envelope["ciphertext"] = "AAAA" + tampered_envelope["ciphertext"][4:]
        grid.deliver_envelope(tampered_envelope)


if __name__ == "__main__":
    run_grid_demo()