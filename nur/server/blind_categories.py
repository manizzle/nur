"""
Blind Category Discovery — threshold reveal protocol.

Contributors propose new categories by submitting hashed names.
The server counts how many independent orgs submit the same hash.
Once threshold is met, contributors vote to reveal the plaintext.
The server NEVER learns a category name until quorum agrees to make it public.

State machine::

    UNKNOWN ──propose()──▶ PENDING ──propose()──▶ THRESHOLD_MET ──vote_reveal()──▶ REVEALED
                            │                      │                                │
                        count < N              count >= N                      quorum met
                        server sees:           server sees:                    server sees:
                          hash only              hash + count                    plaintext!
                                                                                │
                                                                          enters PUBLIC
                                                                          TAXONOMY

    If threshold never met: hash stays opaque forever.
    If quorum not reached: hash stays opaque. Server never learns plaintext.

Protocol:
  1. Contributor hashes category locally: H = SHA-256(category_name:salt)
  2. Contributor submits (H, category_type) to server
  3. Server stores H in pending set, counts unique submitters
  4. When count >= threshold (default 3):
     → Server notifies: "Category H has enough support, ready for reveal"
  5. Contributors who submitted H can vote to reveal by sending (H, plaintext, salt)
  6. Server verifies SHA-256(plaintext:salt) == H
  7. When reveal_quorum (default 2) contributors reveal the same plaintext:
     → Category enters the public taxonomy
     → Aggregation begins on this category
  8. If threshold never met or quorum not reached:
     → H stays opaque forever. Server never learns what it is.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field


def hash_category(name: str, salt: str = "") -> str:
    """Hash a category name for blind submission. Done client-side."""
    return hashlib.sha256(f"{name.strip().lower()}:{salt}".encode()).hexdigest()


def verify_category_hash(name: str, salt: str, expected_hash: str) -> bool:
    """Verify that a plaintext + salt produces the expected hash."""
    return hash_category(name, salt) == expected_hash


@dataclass
class _PendingCategory:
    """A proposed category that hasn't been revealed yet."""
    category_hash: str
    category_type: str  # "threat_actor", "malware", "tool", "technique", "remediation"
    submitter_ids: set = field(default_factory=set)  # opaque contributor IDs (hashed)
    first_seen: float = field(default_factory=time.time)
    # Reveal votes: submitter_id -> (plaintext, salt)
    reveal_votes: dict = field(default_factory=dict)
    revealed_name: str | None = None
    revealed_at: float | None = None


CATEGORY_TYPES = [
    "threat_actor",   # APT groups, ransomware gangs
    "malware",        # Malware families
    "tool",           # Security tools / vendor products
    "technique",      # Attack techniques not yet in MITRE
    "remediation",    # New remediation approaches
    "campaign",       # Named campaigns
]


class BlindCategoryDiscovery:
    """
    Threshold reveal protocol for new category discovery.

    The server never sees a category name until:
    1. Multiple independent orgs submit the same hash (discovery_threshold)
    2. A quorum of those orgs vote to reveal it (reveal_quorum)
    """

    def __init__(
        self,
        discovery_threshold: int = 3,
        reveal_quorum: int = 2,
    ):
        self.discovery_threshold = discovery_threshold
        self.reveal_quorum = reveal_quorum
        self._pending: dict[str, _PendingCategory] = {}  # hash -> PendingCategory
        self._revealed: dict[str, str] = {}  # hash -> revealed plaintext name
        self._revealed_categories: list[dict] = []  # ordered list of revealed categories

    def propose_category(
        self,
        category_hash: str,
        category_type: str,
        submitter_id: str,
    ) -> dict:
        """
        Propose a new category by submitting its hash.

        Returns status: how many orgs have proposed this, whether threshold is met.
        The server never sees the plaintext at this stage.
        """
        if category_type not in CATEGORY_TYPES:
            return {"error": f"Invalid category_type. Must be one of: {CATEGORY_TYPES}"}

        if len(category_hash) != 64:
            return {"error": "category_hash must be a 64-char hex SHA-256 hash"}

        # Already revealed?
        if category_hash in self._revealed:
            return {
                "status": "already_revealed",
                "category_hash": category_hash,
                "revealed_name": self._revealed[category_hash],
            }

        # Create or update pending entry
        if category_hash not in self._pending:
            self._pending[category_hash] = _PendingCategory(
                category_hash=category_hash,
                category_type=category_type,
            )

        entry = self._pending[category_hash]
        entry.submitter_ids.add(submitter_id)

        count = len(entry.submitter_ids)
        ready = count >= self.discovery_threshold

        return {
            "status": "threshold_met" if ready else "pending",
            "category_hash": category_hash,
            "category_type": category_type,
            "supporter_count": count,
            "threshold": self.discovery_threshold,
            "ready_for_reveal": ready,
        }

    def check_threshold(self, category_hash: str) -> dict:
        """Check if a proposed category has reached the discovery threshold."""
        if category_hash in self._revealed:
            return {
                "status": "revealed",
                "category_hash": category_hash,
                "revealed_name": self._revealed[category_hash],
            }

        entry = self._pending.get(category_hash)
        if not entry:
            return {
                "status": "unknown",
                "category_hash": category_hash,
                "supporter_count": 0,
                "threshold": self.discovery_threshold,
                "ready_for_reveal": False,
            }

        count = len(entry.submitter_ids)
        return {
            "status": "threshold_met" if count >= self.discovery_threshold else "pending",
            "category_hash": category_hash,
            "category_type": entry.category_type,
            "supporter_count": count,
            "threshold": self.discovery_threshold,
            "ready_for_reveal": count >= self.discovery_threshold,
        }

    def vote_reveal(
        self,
        category_hash: str,
        plaintext: str,
        salt: str,
        submitter_id: str,
    ) -> dict:
        """
        Vote to reveal a category's plaintext name.

        The submitter provides the plaintext + salt, and we verify
        SHA-256(plaintext:salt) == category_hash. Once reveal_quorum
        submitters independently reveal the same plaintext, the
        category enters the public taxonomy.
        """
        # Verify the hash matches
        if not verify_category_hash(plaintext, salt, category_hash):
            return {"error": "Hash verification failed \u2014 plaintext + salt does not match category_hash"}

        # Already revealed?
        if category_hash in self._revealed:
            return {
                "status": "already_revealed",
                "category_hash": category_hash,
                "revealed_name": self._revealed[category_hash],
            }

        entry = self._pending.get(category_hash)
        if not entry:
            return {"error": "Category hash not found in pending proposals"}

        # Must have reached threshold
        if len(entry.submitter_ids) < self.discovery_threshold:
            return {
                "error": "Discovery threshold not yet met",
                "supporter_count": len(entry.submitter_ids),
                "threshold": self.discovery_threshold,
            }

        # Must be a submitter
        if submitter_id not in entry.submitter_ids:
            return {"error": "Only original proposers can vote to reveal"}

        # Record vote
        normalized = plaintext.strip().lower()
        entry.reveal_votes[submitter_id] = (normalized, salt)

        # Count votes for this specific plaintext
        vote_count = sum(
            1 for (pt, _) in entry.reveal_votes.values()
            if pt == normalized
        )

        if vote_count >= self.reveal_quorum:
            # Quorum reached — reveal the category
            entry.revealed_name = normalized
            entry.revealed_at = time.time()
            self._revealed[category_hash] = normalized
            self._revealed_categories.append({
                "category_hash": category_hash,
                "name": normalized,
                "category_type": entry.category_type,
                "supporter_count": len(entry.submitter_ids),
                "revealed_at": entry.revealed_at,
            })

            return {
                "status": "revealed",
                "category_hash": category_hash,
                "revealed_name": normalized,
                "category_type": entry.category_type,
                "supporter_count": len(entry.submitter_ids),
                "reveal_votes": vote_count,
            }

        return {
            "status": "vote_recorded",
            "category_hash": category_hash,
            "reveal_votes": vote_count,
            "reveal_quorum": self.reveal_quorum,
            "remaining": self.reveal_quorum - vote_count,
        }

    def get_pending_categories(self, min_supporters: int = 0) -> list[dict]:
        """List pending (unrevealed) categories with their support counts."""
        result = []
        for h, entry in self._pending.items():
            if entry.revealed_name is not None:
                continue
            count = len(entry.submitter_ids)
            if count >= min_supporters:
                result.append({
                    "category_hash": h,
                    "category_type": entry.category_type,
                    "supporter_count": count,
                    "threshold": self.discovery_threshold,
                    "ready_for_reveal": count >= self.discovery_threshold,
                    "first_seen": entry.first_seen,
                })
        result.sort(key=lambda x: -x["supporter_count"])
        return result

    def get_revealed_categories(self) -> list[dict]:
        """List all categories that have been revealed through quorum."""
        return list(self._revealed_categories)

    @property
    def pending_count(self) -> int:
        return sum(1 for e in self._pending.values() if e.revealed_name is None)

    @property
    def revealed_count(self) -> int:
        return len(self._revealed)


__all__ = [
    "BlindCategoryDiscovery",
    "CATEGORY_TYPES",
    "hash_category",
    "verify_category_hash",
]
