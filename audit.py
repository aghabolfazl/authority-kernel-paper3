"""Minimal tamper-evident hash-chained audit log (not a secure remote ledger)."""
from __future__ import annotations
import hashlib
import json
import threading
from typing import Any


class AuditLog:
    def __init__(self) -> None:
        self._events: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    @staticmethod
    def _canonical(event: dict[str, Any]) -> bytes:
        return json.dumps(event, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")

    def append(self, event: dict[str, Any]) -> str:
        with self._lock:
            previous = self._events[-1]["hash"] if self._events else "0" * 64
            payload = dict(event)
            payload["previous_hash"] = previous
            payload["hash"] = hashlib.sha256(self._canonical(payload)).hexdigest()
            self._events.append(payload)
            return payload["hash"]

    def events(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(event) for event in self._events]

    def verify(self) -> bool:
        with self._lock:
            previous = "0" * 64
            for stored in self._events:
                event = dict(stored)
                claimed_hash = event.pop("hash", None)
                if event.get("previous_hash") != previous:
                    return False
                calculated = hashlib.sha256(self._canonical({**event, "hash": claimed_hash})).hexdigest()
                # append() hashes the event before adding its own hash field.
                payload = dict(event)
                payload.pop("previous_hash", None) if False else None
                calculated = hashlib.sha256(self._canonical(event)).hexdigest()
                if claimed_hash != calculated:
                    return False
                previous = claimed_hash
            return True
