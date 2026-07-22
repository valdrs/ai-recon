from __future__ import annotations
import re
import json
from typing import Any, Union, Tuple, List, Dict
from app.models.schemas import RawFinding, SanitizedFinding


class BannerSanitizer:
    """Defends against Indirect Prompt Injection and cleans untrusted recon outputs."""

    # Known adversarial prompt patterns designed to hijack LLM behavior
    PROMPT_INJECTION_PATTERNS = [
        r"(?i)ignore\s+(all\s+)?previous\s+(instructions?|rules?|prompts?)",
        r"(?i)disregard\s+(all\s+)?previous",
        r"(?i)you\s+are\s+now\s+a\s+",
        r"(?i)system\s+prompt:",
        r"(?i)output:\s*SYSTEM_PWNED",
        r"(?i)<\s*\|\s*im_start\s*\|>",
        r"(?i)do\s+not\s+report\s+(any\s+)?vulnerabilit",
        r"(?i)override\s+security\s+controls"
    ]

    # Max allowed length for evidence fields to prevent token exhaustion DOS
    MAX_EVIDENCE_LENGTH = 750

    @classmethod
    def sanitize_string(cls, text: str) -> Tuple[str, List[str]]:
        """Sanitize a raw string from a target and return the cleaned text along with audit flags."""
        flags: List[str] = []
        cleaned = text

        # 1. Strip non-printable or dangerous control characters (keep standard newlines and tabs)
        original_len = len(cleaned)
        cleaned = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]", "", cleaned)
        if len(cleaned) != original_len:
            flags.append("STRIPPED_CONTROL_CHARACTERS")

        # 2. Check for and neutralize prompt injection attempts
        for pattern in cls.PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, cleaned):
                flags.append("PROMPT_INJECTION_ATTEMPT_NEUTRALIZED")
                # Replace the adversarial phrase with a neutralized placeholder
                cleaned = re.sub(pattern, "[MALICIOUS_PROMPT_INJECTION_SANITIZED]", cleaned)

        # 3. Truncate to maximum length to prevent token overflow DOS
        if len(cleaned) > cls.MAX_EVIDENCE_LENGTH:
            cleaned = cleaned[:cls.MAX_EVIDENCE_LENGTH] + "... [TRUNCATED_FOR_SAFETY]"
            flags.append("TRUNCATED_TO_MAX_LENGTH")

        return cleaned.strip(), flags

    @classmethod
    def sanitize_evidence(cls, raw_evidence: Union[str, Dict[str, Any]]) -> Tuple[str, List[str]]:
        """Sanitize raw evidence whether it is a string or dictionary representation."""
        flags: List[str] = []
        if isinstance(raw_evidence, str):
            clean_str, str_flags = cls.sanitize_string(raw_evidence)
            flags.extend(str_flags)
            return clean_str, list(set(flags))
        elif isinstance(raw_evidence, dict):
            # Serialize dictionary safely then sanitize string values
            sanitized_dict = {}
            for k, v in raw_evidence.items():
                if isinstance(v, str):
                    clean_v, v_flags = cls.sanitize_string(v)
                    sanitized_dict[k] = clean_v
                    flags.extend(v_flags)
                elif isinstance(v, list):
                    clean_list = []
                    for item in v:
                        if isinstance(item, str):
                            clean_item, item_flags = cls.sanitize_string(item)
                            clean_list.append(clean_item)
                            flags.extend(item_flags)
                        else:
                            clean_list.append(item)
                    sanitized_dict[k] = clean_list
                else:
                    sanitized_dict[k] = v
            return json.dumps(sanitized_dict, indent=2), list(set(flags))
        else:
            return str(raw_evidence), flags

    @classmethod
    def sanitize_finding(cls, finding: RawFinding) -> SanitizedFinding:
        """Convert a RawFinding into a secure, sanitized SanitizedFinding."""
        clean_title, title_flags = cls.sanitize_string(finding.title)
        clean_desc, desc_flags = cls.sanitize_string(finding.description)
        clean_evidence, evidence_flags = cls.sanitize_evidence(finding.raw_evidence)

        all_flags = list(set(title_flags + desc_flags + evidence_flags))

        return SanitizedFinding(
            finding_id=finding.finding_id,
            module=finding.module,
            title=clean_title,
            description=clean_desc,
            evidence_clean=clean_evidence,
            port=finding.port,
            protocol=finding.protocol,
            sanitization_flags=all_flags
        )

    @classmethod
    def sanitize_findings_list(cls, findings: List[RawFinding]) -> Tuple[List[SanitizedFinding], Dict[str, Any]]:
        """Sanitize a list of findings and produce a summary of defensive actions."""
        sanitized_list = []
        injection_count = 0
        truncation_count = 0

        for f in findings:
            clean_f = cls.sanitize_finding(f)
            if "PROMPT_INJECTION_ATTEMPT_NEUTRALIZED" in clean_f.sanitization_flags:
                injection_count += 1
            if "TRUNCATED_TO_MAX_LENGTH" in clean_f.sanitization_flags:
                truncation_count += 1
            sanitized_list.append(clean_f)

        summary = {
            "total_findings_processed": len(findings),
            "prompt_injections_neutralized": injection_count,
            "evidence_truncations_applied": truncation_count,
            "status": "SECURE_PASSTHROUGH" if injection_count == 0 else "ADVERSARIAL_PAYLOAD_MITIGATED"
        }
        return sanitized_list, summary


banner_sanitizer = BannerSanitizer()
