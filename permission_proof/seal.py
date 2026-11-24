"""Hash-chained, write-once sealed certificate versions.

A sealed envelope embeds its certificate (which embeds the exact effective
world snapshot and water-mark vector), links to the previous envelope hash and
carries its own SHA-256 ``envelope_hash``.  Seal files are created once and
marked read-only; :class:`SealStore` refuses to overwrite a version.

A late revocation therefore yields a *new* envelope while the bytes and hash
of an older sealed version stay unchanged and independently verifiable.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canon import canonical_bytes, sha256_hex
from .certificate import verify_certificate

SEAL_SCHEMA = "perm-proof/seal/v1"
GENESIS_HASH = "0" * 64
LEDGER_NAME = "ledger.jsonl"


class ImmutableSealError(RuntimeError):
    """Raised when code attempts to rewrite an already sealed version."""


def build_envelope(
    *,
    seq: int,
    version_id: str,
    label: str,
    certificate: dict[str, Any],
    prev_hash: str,
    watermark_vector: dict[str, int] | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "schema": SEAL_SCHEMA,
        "seq": seq,
        "version_id": version_id,
        "label": label,
        "prev_hash": prev_hash,
        "watermark_vector": watermark_vector
        or certificate.get("watermark_vector", {}),
        "cert_id": certificate.get("cert_id"),
        "cert_hash": certificate.get("cert_hash"),
        "certificate": certificate,
    }
    body["envelope_hash"] = sha256_hex(
        {k: v for k, v in body.items() if k != "envelope_hash"}
    )
    return body


def verify_envelope(envelope: dict[str, Any], *, expected_prev: str | None = None) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    if not isinstance(envelope, dict):
        return {
            "valid": False,
            "version_id": None,
            "seq": None,
            "checks": [
                {
                    "name": "envelope_is_object",
                    "ok": False,
                    "detail": f"got {type(envelope)!r}",
                }
            ],
            "certificate_verification": None,
        }

    claimed = envelope.get("envelope_hash")
    actual = sha256_hex(
        {k: v for k, v in envelope.items() if k != "envelope_hash"}
    )
    hash_ok = bool(claimed) and claimed == actual
    checks.append({"name": "envelope_hash_integrity", "ok": hash_ok, "detail": actual})

    if expected_prev is not None:
        prev_ok = envelope.get("prev_hash") == expected_prev
        checks.append(
            {
                "name": "prev_hash_link",
                "ok": prev_ok,
                "detail": f"expected={expected_prev} got={envelope.get('prev_hash')}",
            }
        )

    cert = envelope.get("certificate", {})
    if not isinstance(cert, dict):
        checks.append(
            {"name": "embedded_certificate_present", "ok": False,
             "detail": f"got {type(cert)!r}"}
        )
        return {
            "valid": False,
            "version_id": envelope.get("version_id") if isinstance(envelope, dict) else None,
            "seq": envelope.get("seq") if isinstance(envelope, dict) else None,
            "checks": checks,
            "certificate_verification": None,
        }
    cert_hash_link_ok = cert.get("cert_hash") == envelope.get("cert_hash")
    checks.append(
        {"name": "envelope_commits_cert_hash", "ok": cert_hash_link_ok}
    )

    try:
        cert_result = verify_certificate(cert)
    except Exception as exc:  # noqa: BLE001 - verification must be total
        cert_result = {"valid": False, "passed_count": 0, "check_count": 1,
                       "checks": [{"name": "verifier_exception", "ok": False,
                                   "detail": repr(exc)}]}
    checks.append(
        {
            "name": "embedded_certificate_valid",
            "ok": cert_result["valid"],
            "detail": f"{cert_result['passed_count']}/{cert_result['check_count']} checks",
        }
    )

    return {
        "valid": all(c["ok"] for c in checks),
        "version_id": envelope.get("version_id"),
        "seq": envelope.get("seq"),
        "checks": checks,
        "certificate_verification": cert_result,
    }


def _write_readonly_json(path: Path, obj: dict[str, Any]) -> str:
    data = json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=False).encode("utf-8")
    path.write_bytes(data)
    digest = sha256_hex(data)
    try:
        os.chmod(path, stat.S_IREAD)
    except OSError:
        # Read-only bit is best-effort on non-Windows; hash chain still enforces.
        pass
    return digest


@dataclass
class SealRecord:
    version_id: str
    seq: int
    path: str
    envelope_hash: str
    file_sha256_at_seal: str


class SealStore:
    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.ledger_path = self.directory / LEDGER_NAME
        self.records: list[SealRecord] = []
        self._last_hash = GENESIS_HASH
        self._seq = 0

    def seal_version(
        self,
        version_id: str,
        certificate: dict[str, Any],
        label: str,
        *,
        watermark_vector: dict[str, int] | None = None,
    ) -> SealRecord:
        path = self.directory / f"{version_id}.json"
        if path.exists():
            raise ImmutableSealError(
                f"sealed version already exists and cannot be rewritten: {path}"
            )
        self._seq += 1
        envelope = build_envelope(
            seq=self._seq,
            version_id=version_id,
            label=label,
            certificate=certificate,
            prev_hash=self._last_hash,
            watermark_vector=watermark_vector,
        )
        file_digest = _write_readonly_json(path, envelope)
        record = SealRecord(
            version_id=version_id,
            seq=self._seq,
            path=str(path),
            envelope_hash=envelope["envelope_hash"],
            file_sha256_at_seal=file_digest,
        )
        self.records.append(record)
        with self.ledger_path.open("a", encoding="utf-8") as fh:
            fh.write(
                json.dumps(
                    {
                        "seq": record.seq,
                        "version_id": record.version_id,
                        "envelope_hash": record.envelope_hash,
                        "prev_hash": envelope["prev_hash"],
                        "cert_hash": certificate.get("cert_hash"),
                        "file": path.name,
                        "file_sha256": file_digest,
                        "label": label,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                )
                + "\n"
            )
        self._last_hash = record.envelope_hash
        return record

    # ------------------------------------------------------------------ #
    def verify_chain(self) -> dict[str, Any]:
        """Verify every ``SEAL-*.json`` and its link / recorded file hash."""
        files = sorted(self.directory.glob("SEAL-*.json"))
        prev = GENESIS_HASH
        version_results: list[dict[str, Any]] = []
        all_ok = True
        for path in files:
            try:
                raw = path.read_bytes()
                envelope = json.loads(raw.decode("utf-8"))
                if not isinstance(envelope, dict):
                    raise ValueError("seal file top-level JSON is not an object")
                result = verify_envelope(envelope, expected_prev=prev)
                current_file_hash = sha256_hex(raw)

                ledger_hash: str | None = None
                if self.ledger_path.exists():
                    for line in self.ledger_path.read_text(encoding="utf-8").splitlines():
                        row = json.loads(line)
                        if row.get("version_id") == envelope.get("version_id"):
                            ledger_hash = row.get("file_sha256")
                file_unchanged = ledger_hash is None or ledger_hash == current_file_hash
                result["file_sha256_now"] = current_file_hash
                result["ledger_file_sha256"] = ledger_hash
                result["file_unchanged_since_seal"] = file_unchanged
                ok = result["valid"] and file_unchanged
                all_ok &= ok
                version_results.append(
                    {
                        "version_id": envelope.get("version_id"),
                        "label": envelope.get("label"),
                        "valid": result["valid"],
                        "file_unchanged": file_unchanged,
                        "envelope_hash": envelope.get("envelope_hash"),
                    }
                )
                prev = envelope.get("envelope_hash", prev)
            except Exception as exc:  # noqa: BLE001 - one bad file must not hide the rest
                all_ok = False
                version_results.append(
                    {
                        "version_id": path.stem,
                        "label": None,
                        "valid": False,
                        "file_unchanged": False,
                        "error": repr(exc),
                    }
                )
        return {
            "valid": all_ok,
            "sealed_version_count": len(files),
            "versions": version_results,
        }


def load_envelope(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_bytes().decode("utf-8"))


def tamper_probe(envelope: dict[str, Any]) -> dict[str, Any]:
    """Return a verification report for a mutilated copy (never written)."""
    import copy

    if not isinstance(envelope, dict):
        return verify_envelope(envelope)  # type: ignore[arg-type]  # -> invalid guard

    mutated = copy.deepcopy(envelope)
    cert = mutated.get("certificate")
    if not isinstance(cert, dict):
        mutated["certificate"] = {"chosen_exceptions": ["EXC-TAMPERED"]}
    else:
        chosen = cert.get("chosen_exceptions", [])
        if not isinstance(chosen, (list, tuple)):
            chosen = []
        cert["chosen_exceptions"] = list(chosen) + ["EXC-TAMPERED"]
    mutated["label"] = str(mutated.get("label", "")) + " [tampered]"
    return verify_envelope(mutated)
