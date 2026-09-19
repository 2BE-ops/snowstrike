"""
Verification gate for SnowStrike agent results.

Challenges agent results that claim offensive success (credential discovery,
shell/access obtained, confirmed vulnerabilities) by making a lightweight
LLM call on the compaction tier to verify that evidence supports the claim.

Results that fail verification are tagged so the orchestrator can handle
them appropriately (e.g. skip shared state updates for fabricated claims).
"""

import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from agents.base_agent import AgentResult
from agents.model_client import create_model_client, resolve_model_for_role

logger = logging.getLogger(__name__)

# Keywords in result summaries that indicate high-value claims worth verifying.
_CREDENTIAL_PATTERNS = re.compile(
    r"(credential|password|hash|token|secret|api.?key|ssh.?key|"
    r"login.?found|auth.*(bypass|crack|dump))",
    re.I,
)
_ACCESS_PATTERNS = re.compile(
    r"(shell\s+(obtained|spawned|opened)|reverse\s+shell|"
    r"(root|admin|system)\s+access|foothold|initial\s+access|"
    r"remote\s+code\s+execution|rce\s+(confirmed|achieved)|"
    r"meterpreter|beacon)",
    re.I,
)
_VULN_CONFIRMED_PATTERNS = re.compile(
    r"(confirmed\s+\S+\s*(injection|vulnerabilit|xss|rce|lfi|rfi|ssrf|xxe)|"
    r"exploit(ed|able)\s+vulnerabilit|"
    r"(sql.?injection|xss|rce|lfi|rfi|ssrf|xxe)\s+(confirmed|exploited|verified)|"
    r"proof.?of.?concept\s+(success|work))",
    re.I,
)


class VerificationStatus(str, Enum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    FABRICATED = "fabricated"


@dataclass
class VerificationResult:
    """Outcome of verifying an agent result."""
    status: VerificationStatus
    reason: str
    original_result: AgentResult


_VERIFICATION_SYSTEM = (
    "You are a penetration test QA reviewer. Your job is to verify whether "
    "an agent's claimed finding is supported by the tool output evidence. "
    "Be strict: only mark VERIFIED if evidence clearly proves the claim."
)

_VERIFICATION_PROMPT_TEMPLATE = """\
An agent claims: {summary}

The evidence provided (last 2000 chars of tool output):
---
{evidence}
---

Does the evidence support the claim? Reply with exactly ONE of:
VERIFIED: [reason] — if evidence clearly supports the claim
UNVERIFIED: [reason] — if evidence is ambiguous or missing
FABRICATED: [reason] — if evidence contradicts the claim"""


class VerificationGate:
    """Challenges agent results that claim offensive success.

    Uses a lightweight LLM call (compaction tier) to verify that claimed
    findings are supported by the tool output evidence.

    Only triggers for results that claim:
    - Credential discovery
    - Shell/access obtained
    - Confirmed vulnerability (not just "possible")
    """

    def __init__(self, model_config: dict = None):
        self._model_config = model_config or {}
        self._model_id = resolve_model_for_role("compaction", self._model_config)
        self._client = create_model_client(self._model_id)

    def should_verify(self, result: AgentResult) -> bool:
        """Return True if the result claims high-value findings worth verifying.

        Only triggers for results that claim credentials, shells/access,
        or confirmed vulnerabilities. Does NOT trigger for recon results,
        failed attempts, or informational findings.
        """
        if not result.success:
            return False

        summary = result.summary or ""
        findings_str = str(result.findings) if result.findings else ""
        combined = f"{summary} {findings_str}"

        if _CREDENTIAL_PATTERNS.search(combined):
            return True
        if _ACCESS_PATTERNS.search(combined):
            return True
        if _VULN_CONFIRMED_PATTERNS.search(combined):
            return True

        return False

    def verify(self, result: AgentResult) -> VerificationResult:
        """Make a cheap LLM call to verify the agent's claimed findings.

        If the verification call fails for any reason, defaults to UNVERIFIED
        (does not block the pipeline).
        """
        summary = (result.summary or "")[:500]

        # Build evidence from findings and tool output
        evidence_parts = []
        if result.findings:
            evidence_parts.append(str(result.findings)[:1000])
        if result.errors:
            evidence_parts.append(f"Errors: {result.errors[:3]}")
        evidence = "\n".join(evidence_parts)[-2000:] if evidence_parts else "(no evidence)"

        prompt = _VERIFICATION_PROMPT_TEMPLATE.format(
            summary=summary,
            evidence=evidence,
        )

        try:
            response = self._client.messages.create(
                model=self._model_id,
                max_tokens=256,
                system=_VERIFICATION_SYSTEM,
                messages=[{"role": "user", "content": prompt}],
            )

            reply = ""
            for block in response.content:
                if hasattr(block, "text"):
                    reply += block.text
            reply = reply.strip()

            status, reason = self._parse_reply(reply)
            logger.info("[VerificationGate] %s: %s", status.value.upper(), reason)
            return VerificationResult(status=status, reason=reason, original_result=result)

        except Exception as e:
            logger.warning("[VerificationGate] LLM call failed, defaulting to UNVERIFIED: %s", e)
            return VerificationResult(
                status=VerificationStatus.UNVERIFIED,
                reason=f"Verification call failed: {e}",
                original_result=result,
            )

    @staticmethod
    def _parse_reply(reply: str) -> tuple[VerificationStatus, str]:
        """Parse the LLM reply into (status, reason)."""
        reply_upper = reply.upper()

        if reply_upper.startswith("FABRICATED:"):
            reason = reply[len("FABRICATED:"):].strip()
            return VerificationStatus.FABRICATED, reason

        if reply_upper.startswith("VERIFIED:"):
            reason = reply[len("VERIFIED:"):].strip()
            return VerificationStatus.VERIFIED, reason

        if reply_upper.startswith("UNVERIFIED:"):
            reason = reply[len("UNVERIFIED:"):].strip()
            return VerificationStatus.UNVERIFIED, reason

        # Fallback: search for keywords in the reply (strict word-boundary matching)
        # Check UNVERIFIED before VERIFIED to avoid "UNVERIFIED" matching "VERIFIED"
        if re.search(r"\bUNVERIFIED\b", reply_upper):
            return VerificationStatus.UNVERIFIED, reply[:200]
        if re.search(r"\bFABRICATED\b", reply_upper):
            return VerificationStatus.FABRICATED, reply[:200]
        if re.search(r"\bVERIFIED\b", reply_upper):
            return VerificationStatus.VERIFIED, reply[:200]

        # Default to UNVERIFIED when parsing is ambiguous
        return VerificationStatus.UNVERIFIED, reply[:200]
